#!/usr/bin/env python3
"""
Modbus TCP Server (Asyncio version for high concurrency)
Listens for connections from multiple simultaneous Modbus clients.
"""

import asyncio
from pymodbus.server import StartAsyncTcpServer
from pymodbus.device import ModbusDeviceIdentification
from pymodbus.datastore import ModbusSequentialDataBlock, ModbusSlaveContext, ModbusServerContext
import logging
import math
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
log = logging.getLogger(__name__)

async def electrical_plant_simulator(context, unit_id=0x00, period=0.5):
    """
    Simulates a simple electrical plant / feeder asynchronously.
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

    # "plant constants"
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
            # Optional: auto-clear the reset coil
            context[unit_id].setValues(1, 1, [0])

        # Breaker logic: if tripped, force open
        if trip_active:
            breaker_closed = 0
        else:
            breaker_closed = 1 if close_cmd else 0

        # ---- Simulate electrical behavior ----
        if not breaker_closed:
            I_x10 = 0
            P_x10 = 0
            Q_x10 = 0
            S_x10 = 0

            V += int((Vset - V) * 0.10)
            F += int((Fset - F) * 0.05)
            PF += int((PFset - PF) * 0.10)

        else:
            demand_x10 = max(0, Pset_x10 + int(15 * math.sin(t / 6.0)) + random.randint(-5, 5))

            PF += int((PFset - PF) * 0.08) + random.randint(-2, 2)
            PF = max(100, min(PF, 1000))

            P_x10 = demand_x10
            S_x10 = int(P_x10 * 1000 / max(PF, 1))
            q = int(max(0, S_x10 * S_x10 - P_x10 * P_x10) ** 0.5)
            Q_x10 = q

            S_kVA = S_x10 / 10.0
            I = (S_kVA * 1000.0) / (1.732 * max(V, 1))
            I_x10 = int(I * 10)

            if avr_enable:
                V += int((Vset - V) * 0.15) + random.randint(-1, 1)
            else:
                droop = int((I_x10 / 10.0) * 0.02)
                V_target = max(0, Vset - droop)
                V += int((V_target - V) * 0.10) + random.randint(-1, 1)

            load_effect = int((P_x10 / 10.0) * 0.3)
            F_target = Fset - load_effect if not avr_enable else Fset
            F += int((F_target - F) * 0.05) + random.randint(-2, 2)

        V = max(0, min(V, 10000))
        F = max(4500, min(F, 6500))

        # ---- Protection / alarms ----
        overcurrent_alarm = int(I_x10 > overcurrent_trip_Ax10)
        undervoltage_alarm = int(V < V_min_alarm)
        underfreq = int(F < underfreq_alarm)
        overfreq = int(F > overfreq_alarm)

        if breaker_closed and overcurrent_alarm:
            trip_active = 1
            breaker_closed = 0

        # ---- Publish to datastore ----
        context[unit_id].setValues(2, 0, [
            int(breaker_closed),
            int(trip_active),
            int(overcurrent_alarm),
            int(undervoltage_alarm),
            int(overfreq),
            int(underfreq),
        ])

        context[unit_id].setValues(4, 0, [V, I_x10, P_x10, Q_x10, S_x10, PF, F])

        t += period
        # Use asyncio.sleep instead of time.sleep so we don't block the server loop!
        await asyncio.sleep(period)


async def run_server(host='0.0.0.0', port=5020):
    """
    Start the Async Modbus TCP server.
    """
    store = ModbusSlaveContext(
        di=ModbusSequentialDataBlock(0, [0] * 100),
        co=ModbusSequentialDataBlock(0, [0] * 100),
        hr=ModbusSequentialDataBlock(0, [0] * 100),
        ir=ModbusSequentialDataBlock(0, [0] * 100)
    )
    
    context = ModbusServerContext(slaves=store, single=True)
    
    identity = ModbusDeviceIdentification()
    identity.VendorName = 'Custom Modbus Server'
    identity.ProductCode = 'MBS'
    identity.VendorUrl = 'http://github.com'
    identity.ProductName = 'Async Modbus TCP Server'
    identity.ModelName = 'Modbus Server'
    identity.MajorMinorRevision = '1.1.0'
    
    log.info(f"Starting Async Modbus TCP Server on {host}:{port}")
    log.info("Server is ready to accept high-concurrency connections")
    
    # Launch the simulator as a background async task
    asyncio.create_task(electrical_plant_simulator(context, 0x00, 0.5))

    # Start the server (this runs infinitely)
    await StartAsyncTcpServer(
        context=context,
        identity=identity,
        address=(host, port)
    )

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Async Modbus TCP Server')
    parser.add_argument('--host', default='0.0.0.0', help='IP address to bind to (default: 0.0.0.0)')
    parser.add_argument('--port', type=int, default=5020, help='Port to listen on (default: 5020)')
    
    args = parser.parse_args()
    
    try:
        # Use asyncio.run to execute the main async function
        asyncio.run(run_server(host=args.host, port=args.port))
    except KeyboardInterrupt:
        log.info("Server stopped by user")
    except Exception as e:
        log.error(f"Server error: {e}")

