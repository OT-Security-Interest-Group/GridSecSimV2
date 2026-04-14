#!/usr/bin/env python
"""
read_bulk.py - Bulk-read holding registers from a Modbus/TCP target.

Reads large contiguous blocks of registers (125 per request, the Modbus max)
to simulate data exfiltration from an unauthorized source.

Requires: pip install pymodbus
"""

import argparse
import sys
import time
from pymodbus.client import ModbusTcpClient


def run_once(client, target, start, total, port, unit):
    print(f"[*] Bulk reading {total} registers starting at {start} from {target}:{port} unit={unit}\n")

    MAX_PER_REQ = 125
    addr = start
    extracted = 0

    while extracted < total:
        batch = min(MAX_PER_REQ, total - extracted)
        result = client.read_holding_registers(addr, count=batch, slave=unit)

        if result.isError():
            print(f"  [-] Addr {addr}: error ({result})")
        else:
            print(f"  [+] Addr {addr}-{addr + batch - 1}: read {batch} registers")
            extracted += batch

        addr += batch

    return extracted


def main():
    parser = argparse.ArgumentParser(description="Bulk-read holding registers (FC3)")
    parser.add_argument("target", help="Target IP")
    parser.add_argument("--start", type=int, default=0)
    parser.add_argument("--total", type=int, default=1000)
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--unit", type=int, default=0)
    parser.add_argument("--loops", type=int, default=1, help="Repeat full read sweep this many times")
    parser.add_argument(
        "--sleep-between",
        type=float,
        default=0.0,
        help="Seconds to sleep between loops (jitter-friendly pause)",
    )
    args = parser.parse_args()

    if args.loops < 1:
        print("[!] loops must be >= 1", file=sys.stderr)
        sys.exit(1)

    client = ModbusTcpClient(args.target, port=args.port, timeout=2)
    if not client.connect():
        print(f"[!] Cannot connect to {args.target}:{args.port}")
        sys.exit(1)

    grand = 0
    for i in range(args.loops):
        if args.loops > 1:
            print(f"\n[*] Loop {i + 1}/{args.loops}")
        n = run_once(client, args.target, args.start, args.total, args.port, args.unit)
        grand += n
        if i + 1 < args.loops and args.sleep_between > 0:
            time.sleep(args.sleep_between)

    client.close()
    print(f"\n[*] Done - extracted {grand} register reads across {args.loops} loop(s)")


if __name__ == "__main__":
    main()
