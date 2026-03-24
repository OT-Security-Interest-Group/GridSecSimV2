#!/usr/bin/env python3
"""
Modbus TCP Server
Listens for connections from Modbus clients on separate networks.
"""

from pymodbus.server import StartTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
import logging
import threading
import time
import math
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)

def electrical_plant_simulator(context, unit_id=0x00, period=0.5):
    """
    Simulates a simple electrical plant / feeder:
    - Breaker connect/disconnect
    - Voltage regulation (AVR)
    - Load demand affects current and power
    - Frequency drifts slightly with load unless controlled
    - Trips on overcurrent, with latched trip until reset
    """

    # ---- Defaults (setpoints in HR) ----
    # HR0: Vset (V), HR1: Pset (kW*10), HR2: Fset (Hz*100), HR3: PFset (x1000)
    context[unit_id].setValues(3, 0, [480, 350, 6000, 950])

    # ---- Internal state ----
    breaker_closed = 0
    trip_active = 0

    # Measurements (scaled)
    V = 480          # V
    F = 6000         # Hz * 100
    PF = 950         # x1000

    # “plant constants”
    V_min_alarm = 420
    overcurrent_trip_Ax10 = 2500   # 250.0 A
    underfreq_alarm = 5900         # 59.00 Hz
    overfreq_alarm = 6100          # 61.00 Hz

    t = 0.0

    while True:
        # ---- Read controls ----
        close_cmd = int(context[unit_id].getValues(1, 0, count=1)[0])  # Coil 0
        reset_cmd = int(context[unit_id].getValues(1, 1, count=1)[0])  # Coil 1
        avr_enable = int(context[unit_id].getValues(1, 2, count=1)[0])  # Coil 2

        Vset, Pset_x10, Fset, PFset = context[unit_id].getValues(3, 0, count=4)

        # Reset is a pulse — clear trip + allow breaker to close again
        if reset_cmd:
            trip_active = 0
            # Optional: auto-clear the reset coil (so user can just pulse it)
            context[unit_id].setValues(1, 1, [0])

        # Breaker logic: if tripped, force open
        if trip_active:
            breaker_closed = 0
        else:
            breaker_closed = 1 if close_cmd else 0

        # ---- Simulate electrical behavior ----
        # If breaker open -> near-zero current and power, voltage/freq float near nominal
        if not breaker_closed:
            I_x10 = 0
            P_x10 = 0
            Q_x10 = 0
            S_x10 = 0

            # Voltage/freq relax to setpoints slowly
            V += int((Vset - V) * 0.10)
            F += int((Fset - F) * 0.05)
            PF += int((PFset - PF) * 0.10)

        else:
            # Load demand with small oscillation/noise
            demand_x10 = max(0, Pset_x10 + int(15 * math.sin(t / 6.0)) + random.randint(-5, 5))

            # PF tends toward setpoint but with small variation
            PF += int((PFset - PF) * 0.08) + random.randint(-2, 2)
            PF = max(100, min(PF, 1000))  # 0.100 to 1.000

            # Compute apparent power S = P / PF
            # Using scaled: P_x10 (kW*10), PF (x1000)
            P_x10 = demand_x10
            S_x10 = int(P_x10 * 1000 / max(PF, 1))  # kVA*10
            # Reactive power Q = sqrt(S^2 - P^2)
            # all in k*10 units, ok for toy sim
            q = int(max(0, S_x10 * S_x10 - P_x10 * P_x10) ** 0.5)
            Q_x10 = q

            # Current approx: I = (S[kVA] * 1000) / (sqrt(3)*V)
            # S_x10 = kVA*10 => S_kVA = S_x10/10
            S_kVA = S_x10 / 10.0
            I = (S_kVA * 1000.0) / (1.732 * max(V, 1))
            I_x10 = int(I * 10)

            # Voltage regulation: without AVR, voltage droops with current
            if avr_enable:
                # regulate toward Vset
                V += int((Vset - V) * 0.15) + random.randint(-1, 1)
            else:
                droop = int((I_x10 / 10.0) * 0.02)  # ~0.02 V per amp (toy)
                V_target = max(0, Vset - droop)
                V += int((V_target - V) * 0.10) + random.randint(-1, 1)

            # Frequency: slight droop with load if not controlled
            # Keep it realistic-ish: heavier load => slightly lower freq
            load_effect = int((P_x10 / 10.0) * 0.3)  # toy “droop” in (Hz*100) units
            F_target = Fset - load_effect if not avr_enable else Fset
            F += int((F_target - F) * 0.05) + random.randint(-2, 2)

        # Clamp V and F to plausible ranges
        V = max(0, min(V, 10000))
        F = max(4500, min(F, 6500))

        # ---- Protection / alarms ----
        overcurrent_alarm = int(I_x10 > overcurrent_trip_Ax10)
        undervoltage_alarm = int(V < V_min_alarm)
        underfreq = int(F < underfreq_alarm)
        overfreq = int(F > overfreq_alarm)

        # Trip behavior: if breaker closed and overcurrent -> trip & latch
        if breaker_closed and overcurrent_alarm:
            trip_active = 1
            breaker_closed = 0

        # ---- Publish to datastore ----
        # Discrete Inputs (2 = DI): breaker status, trip, alarms
        context[unit_id].setValues(2, 0, [
            int(breaker_closed),
            int(trip_active),
            int(overcurrent_alarm),
            int(undervoltage_alarm),
            int(overfreq),
            int(underfreq),
        ])

        # Input Registers (4 = IR): measurements
        # IR0 V, IR1 I_x10, IR2 P_x10, IR3 Q_x10, IR4 S_x10, IR5 PF, IR6 F
        context[unit_id].setValues(4, 0, [V, I_x10, P_x10, Q_x10, S_x10, PF, F])

        t += period
        time.sleep(period)


def run_server(host='0.0.0.0', port=5020):
    """
    Start the Modbus TCP server.
    
    Args:
        host: IP address to bind to (0.0.0.0 allows connections from any network)
        port: Port number to listen on (default: 5020)
    """
    
    # Initialize data store
    # Create data blocks for different register types
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),    # Discrete Inputs
        co=ModbusSequentialDataBlock(0, [0] * 100),    # Coils
        hr=ModbusSequentialDataBlock(0, [0] * 100),    # Holding Registers
        ir=ModbusSequentialDataBlock(0, [0] * 100)     # Input Registers
    )
    
    # Create server context with single slave
    context = ModbusServerContext(slaves=store, single=True)
    
    # Server identification
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'Custom Modbus Server'
    identity.ProductCode = 'MBS'
    identity.VendorUrl = 'http://github.com'
    identity.ProductName = 'Modbus TCP Server'
    identity.ModelName = 'Modbus Server'
    identity.MajorMinorRevision = '1.0.0'
    
    log.info(f"Starting Modbus TCP Server on {host}:{port}")
    log.info("Server will accept connections from remote networks")
    log.info("Press Ctrl+C to stop the server")

    sim_thread = threading.Thread(
        target=electrical_plant_simulator,
        args=(context, 0x00, 0.5),
        daemon=True
    )
    sim_thread.start()

    # Start the server
    StartTcpServer(
        context=context,
        identity=identity,
        address=(host, port)
    )


if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Modbus TCP Server')
    parser.add_argument('--host', default='0.0.0.0', 
                       help='IP address to bind to (default: 0.0.0.0 for all interfaces)')
    parser.add_argument('--port', type=int, default=5020,
                       help='Port to listen on (default: 5020)')
    
    args = parser.parse_args()
    
    try:
        run_server(host=args.host, port=args.port)
    except KeyboardInterrupt:
        log.info("Server stopped by user")
    except Exception as e:
        log.error(f"Server error: {e}")
