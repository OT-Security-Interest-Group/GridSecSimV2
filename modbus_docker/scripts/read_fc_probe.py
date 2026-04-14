#!/usr/bin/env python
"""
read_fc_probe.py - Probe all read function codes on a Modbus/TCP target.

Tests FC 1 (Read Coils), FC 2 (Read Discrete Inputs), FC 3 (Read Holding
Registers), FC 4 (Read Input Registers) to discover what the device supports.

Requires: pip install pymodbus
"""

import argparse
import sys
import time
from pymodbus.client import ModbusTcpClient


def probe_once(client, target, port, unit):
    print(f"[*] Probing read FCs on {target}:{port} unit={unit}\n")

    probes = [
        ("FC 1  Read Coils", lambda: client.read_coils(0, count=10, slave=unit)),
        ("FC 2  Read Discrete Inputs", lambda: client.read_discrete_inputs(0, count=10, slave=unit)),
        ("FC 3  Read Holding Registers", lambda: client.read_holding_registers(0, count=10, slave=unit)),
        ("FC 4  Read Input Registers", lambda: client.read_input_registers(0, count=10, slave=unit)),
    ]

    for name, fn in probes:
        try:
            result = fn()
            if result.isError():
                print(f"  [-] {name}: error ({result})")
            else:
                print(f"  [+] {name}: supported")
        except Exception as e:
            print(f"  [!] {name}: exception ({e})")


def main():
    parser = argparse.ArgumentParser(description="Probe read function codes")
    parser.add_argument("target", help="Target IP")
    parser.add_argument("port", nargs="?", type=int, default=502)
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

    for i in range(args.loops):
        if args.loops > 1:
            print(f"\n[*] Loop {i + 1}/{args.loops}")
        probe_once(client, args.target, args.port, args.unit)
        if i + 1 < args.loops and args.sleep_between > 0:
            time.sleep(args.sleep_between)

    client.close()
    print("\n[*] Done")


if __name__ == "__main__":
    main()
