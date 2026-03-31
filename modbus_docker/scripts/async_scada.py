#!/usr/bin/env python3
"""
Async SCADA Master Simulator
High-frequency, concurrent reads of real-time telemetry.
Uses asyncio to prevent socket locking and zombie connections.
"""
import asyncio
import random
import logging
import argparse
from pymodbus.client import AsyncModbusTcpClient

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

async def run_scada(host, port, unit_id=0, poll_rate=0.5, client_id=1):
    log = logging.getLogger(f"SCADA-{client_id}")
    client = AsyncModbusTcpClient(host, port=port)
    
    log.info(f"Starting against {host}:{port} at {poll_rate}s intervals.")
    
    while True:
        if not client.connected:
            await client.connect()
            if not client.connected:
                log.warning("Connection failed. Retrying in 2 seconds...")
                await asyncio.sleep(2)
                continue
            else:
                log.info("Successfully connected/reconnected.")

        try:
            # FC 02: Read Discrete Inputs (Status & Alarms)
            await client.read_discrete_inputs(address=0, count=6, slave=unit_id)
            # FC 04: Read Input Registers (V, I, P, Q, S, PF, F)
            await client.read_input_registers(address=0, count=7, slave=unit_id)
            
        except Exception as e:
            log.debug(f"Read error: {e}")
            client.close() # CRITICAL: Clean up the broken socket so the server drops it cleanly
            
        # Jitter prevents network spikes by staggering the requests slightly
        await asyncio.sleep(poll_rate + random.uniform(0.0, 0.15))

async def main():
    parser = argparse.ArgumentParser(description="High-Concurrency SCADA Poller")
    parser.add_argument('--target', required=True, help="Server IP:PORT (e.g., 192.168.1.10:5020)")
    parser.add_argument('--count', type=int, default=1, help="Number of concurrent SCADA nodes to simulate")
    args = parser.parse_args()
    
    host, port_str = args.target.split(':')
    port = int(port_str)
    
    logging.info(f"Spawning {args.count} concurrent SCADA polling clients...")
    
    # Spawn multiple concurrent SCADA tasks
    tasks = []
    for i in range(args.count):
        tasks.append(run_scada(host, port, client_id=i+1))
        
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("SCADA Poller stopped by user.")
