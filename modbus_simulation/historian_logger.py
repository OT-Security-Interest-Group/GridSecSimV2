#!/usr/bin/env python3
"""
Data Historian Simulator
Low-frequency, periodic reads for long-term trending.
"""
import time
import logging
import argparse
from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_historian(host, port, unit_id=0, poll_rate=5.0):
    client = ModbusTcpClient(host, port=port)
    logging.info(f"Starting Historian Logger against {host}:{port} at {poll_rate}s intervals.")
    
    while True:
        if client.connect():
            try:
                # FC 03: Read Holding Registers (Setpoints)
                client.read_holding_registers(address=0, count=4, slave=unit_id)
                # FC 04: Read just Power and Frequency for logging
                client.read_input_registers(address=2, count=5, slave=unit_id)
            except Exception as e:
                logging.debug(f"Historian read error: {e}")
        else:
            logging.warning(f"Historian failed to connect to {host}:{port}")
            time.sleep(2)
            
        time.sleep(poll_rate)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="Server IP:PORT (e.g., 192.168.1.10:5020)")
    args = parser.parse_args()
    
    host, port = args.target.split(':')
    try:
        run_historian(host, int(port))
    except KeyboardInterrupt:
        logging.info("Historian Logger stopped.")
