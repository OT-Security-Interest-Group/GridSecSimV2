#!/usr/bin/env python3
"""
Slow IED/relay-style Modbus reads (FC1 coils + FC3 holding) for benign baseline diversity.
"""
from __future__ import annotations

import argparse
import logging
import random
import time

from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def main() -> None:
    p = argparse.ArgumentParser(description="Benign slow FC1 + FC3 poller")
    p.add_argument("--target", required=True, help="PLC as HOST:PORT")
    p.add_argument("--unit", type=int, default=0)
    p.add_argument("--min-interval", type=float, default=35.0)
    p.add_argument("--max-interval", type=float, default=120.0)
    args = p.parse_args()

    host, port_s = args.target.split(":")
    port = int(port_s)
    client = ModbusTcpClient(host, port=port)
    logging.info(
        "Relay poller %s:%s unit=%s interval %.1f–%.1fs",
        host,
        port,
        args.unit,
        args.min_interval,
        args.max_interval,
    )

    while True:
        time.sleep(random.uniform(args.min_interval, args.max_interval))
        if not client.connect():
            logging.warning("Connect failed; retry in 5s")
            time.sleep(5)
            continue
        try:
            coil_count = random.randint(3, 8)
            client.read_coils(address=0, count=coil_count, slave=args.unit)
            hr_start = random.choice([0, 1, 2])
            hr_count = random.randint(6, 16)
            client.read_holding_registers(address=hr_start, count=hr_count, slave=args.unit)
        except Exception as e:
            logging.warning("Read error: %s", e)
        finally:
            client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("Relay poller stopped.")
