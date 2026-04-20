#!/usr/bin/env python3
"""
Infrequent FC16 multi-register writes (EMS / setpoint schedule style) for benign diversity.
Uses the same holding map as the plant sim (e.g. P setpoint at HR1).
"""
from __future__ import annotations

import argparse
import logging
import random
import time

from pymodbus.client import ModbusTcpClient

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


def main() -> None:
    p = argparse.ArgumentParser(description="Benign slow FC16 EMS-style writer")
    p.add_argument("--target", required=True, help="PLC as HOST:PORT")
    p.add_argument("--unit", type=int, default=0)
    p.add_argument("--min-interval", type=float, default=120.0)
    p.add_argument("--max-interval", type=float, default=360.0)
    args = p.parse_args()

    host, port_s = args.target.split(":")
    port = int(port_s)
    client = ModbusTcpClient(host, port=port)
    logging.info(
        "EMS scheduler %s:%s unit=%s interval %.1f–%.1fs",
        host,
        port,
        args.unit,
        args.min_interval,
        args.max_interval,
    )

    while True:
        time.sleep(random.uniform(args.min_interval, args.max_interval))
        if not client.connect():
            logging.warning("Connect failed; retry in 10s")
            time.sleep(10)
            continue
        try:
            # Light read so EMS "sees" state before tweak (FC4)
            client.read_input_registers(address=0, count=4, slave=args.unit)

            # FC16: small block starting at HR0–2 (setpoints / limits in plant sim)
            start = random.choice([0, 1])
            nregs = random.choice([2, 3, 4])
            values = []
            for i in range(nregs):
                if start + i == 1:
                    values.append(random.randint(240, 460))
                else:
                    values.append(random.randint(0, 500))
            client.write_registers(address=start, values=values, slave=args.unit)
            logging.info("FC16 write addr=%s count=%s sample=%s", start, nregs, values[:2])
        except Exception as e:
            logging.warning("EMS cycle error: %s", e)
        finally:
            client.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logging.info("EMS scheduler stopped.")
