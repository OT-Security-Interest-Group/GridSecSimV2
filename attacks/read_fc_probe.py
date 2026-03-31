#!/usr/bin/env python
"""
read_fc_probe.py - Probe all read function codes on a Modbus/TCP target.

Tests FC 1 (Read Coils), FC 2 (Read Discrete Inputs), FC 3 (Read Holding
Registers), FC 4 (Read Input Registers) to discover what the device supports.

Usage:
    python read_fc_probe.py <target_ip> [port] [unit_id]

    python read_fc_probe.py 192.168.1.100
    python read_fc_probe.py 192.168.1.100 502 1

Requires: pip install pymodbus
"""

import sys
from pymodbus.client import ModbusTcpClient

target = sys.argv[1]
port = int(sys.argv[2]) if len(sys.argv) > 2 else 502
unit = int(sys.argv[3]) if len(sys.argv) > 3 else 1

client = ModbusTcpClient(target, port=port, timeout=2)
if not client.connect():
    print(f"[!] Cannot connect to {target}:{port}")
    sys.exit(1)

print(f"[*] Probing read FCs on {target}:{port} unit={unit}\n")

probes = [
    ("FC 1  Read Coils",             lambda: client.read_coils(0, count=10, slave=unit)),
    ("FC 2  Read Discrete Inputs",   lambda: client.read_discrete_inputs(0, count=10, slave=unit)),
    ("FC 3  Read Holding Registers", lambda: client.read_holding_registers(0, count=10, slave=unit)),
    ("FC 4  Read Input Registers",   lambda: client.read_input_registers(0, count=10, slave=unit)),
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

client.close()
print("\n[*] Done")
