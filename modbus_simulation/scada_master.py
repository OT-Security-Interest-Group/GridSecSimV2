#!/usr/bin/env python3
"""
SCADA Master Simulator
High-frequency, periodic reads of real-time telemetry.
"""
import time
import logging
import argparse
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_scada(host, port, unit_id=0, poll_rate=0.5):
    client = ModbusTcpClient(host, port=port)
    logging.info(f"Starting SCADA Poller against {host}:{port} at {poll_rate}s intervals.")
    
    while True:
        if client.connect():
            try:
                # FC 02: Read Discrete Inputs (Status & Alarms)
                client.read_discrete_inputs(address=0, count=6, slave=unit_id)
                # FC 04: Read Input Registers (V, I, P, Q, S, PF, F)
                client.read_input_registers(address=0, count=7, slave=unit_id)
            except Exception as e:
                logging.debug(f"SCADA read error: {e}")
        else:
            logging.warning(f"SCADA failed to connect to {host}:{port}")
            time.sleep(2)
            
        time.sleep(poll_rate)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="Server IP:Port"
    args = parser.parse_args()
    
    host, port = args.target.split(':')
    try:
        run_scada(host, int(port))
    except KeyboardInterrupt:
        logging.info("SCADA Poller stopped.")
