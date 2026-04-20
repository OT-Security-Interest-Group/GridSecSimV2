#!/usr/bin/env python3
"""
Operator HMI Simulator
Sporadic, event-driven reads and writes simulating human grid management.
"""
import time
import random
import logging
import argparse
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_operator(host, port, unit_id: int = 0):
    client = ModbusTcpClient(host, port=port)
    logging.info(f"Starting Operator HMI against {host}:{port} (Sporadic events).")
    
    while True:
        # Simulate human wait times between checking the screen or taking action
        time.sleep(random.uniform(5.0, 20.0))
        
        if not client.connect():
            logging.warning(f"Operator failed to connect to {host}:{port}")
            continue

        try:
            # Check for trips first (FC 02)
            di_result = client.read_discrete_inputs(address=1, count=1, slave=unit_id)
            if not di_result.isError() and di_result.bits[0] == True:
                logging.warning("Operator noticed a trip! Initiating reset.")
                client.write_coil(address=1, value=True, slave=unit_id) # Reset fault
                time.sleep(1)
                client.write_coil(address=0, value=True, slave=unit_id) # Close breaker
                continue # Handle fault, then go back to waiting

            # Sporadic Action 1: Adjust power demand based on grid load
            if random.random() < 0.3: 
                new_pset = random.randint(250, 450)
                logging.info(f"Operator adjusting Power Setpoint to {new_pset/10.0}kW")
                client.write_register(address=1, value=new_pset, slave=unit_id) # FC 06

            # Sporadic Action 2: Toggle AVR
            elif random.random() < 0.1: 
                avr_state = random.choice([True, False])
                logging.info(f"Operator setting AVR Enable to {avr_state}")
                client.write_coil(address=2, value=avr_state, slave=unit_id) # FC 05

        except Exception as e:
            logging.debug(f"Operator communication error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="Server IP:PORT (e.g., 192.168.1.10:5020)")
    parser.add_argument('--unit', type=int, default=0, help="Modbus unit / slave id")
    args = parser.parse_args()
    
    host, port = args.target.split(':')
    try:
        run_operator(host, int(port), unit_id=args.unit)
    except KeyboardInterrupt:
        logging.info("Operator HMI stopped.")
