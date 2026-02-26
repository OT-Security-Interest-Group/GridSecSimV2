import time
import csv
import random
import os
from datetime import datetime
from pymodbus.client import ModbusTcpClient

# Target the static IP assigned to the tx_rtu in the docker-compose.yml
TARGET_IP = '10.30.0.9' 
PORT = 502
LOG_FILE = '/app/scripts/scada_poll_log.csv'

def run_master():
    client = ModbusTcpClient(TARGET_IP, port=PORT)
    
    # Create the CSV log file and write the header if it doesn't exist
    if not os.path.exists(LOG_FILE):
        with open(LOG_FILE, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(['timestamp', 'target_ip', 'function_code', 'register_0_115kV', 'register_1_230kV', 'register_2_MW'])
    
    print(f"SCADA Master starting. Attempting to poll TX RTU at {TARGET_IP}:{PORT}...")
    
    while True:
        if client.connect():
            try:
                # Read 3 Holding Registers (Function Code 3) starting at Address 0
                result = client.read_holding_registers(address=1, count=3, slave=1)
                
                if not result.isError():
                    vals = result.registers
                    timestamp = datetime.now().isoformat()
                    
                    # Log the transaction to CSV for ML training
                    with open(LOG_FILE, mode='a', newline='') as file:
                        writer = csv.writer(file)
                        writer.writerow([timestamp, TARGET_IP, 3, vals[0], vals[1], vals[2]])
                    
                    print(f"[{timestamp}] Read Success: 115kV Line={vals[0]/10}kV | 230kV Line={vals[1]/10}kV | Power={vals[2]}MW")
                else:
                    print(f"[{datetime.now().isoformat()}] Modbus Error: Received exception from RTU.")
                    
            except Exception as e:
                print(f"Exception during polling: {e}")
                
            finally:
                client.close()
        else:
            print(f"[{datetime.now().isoformat()}] Connection to {TARGET_IP} failed. Retrying...")
        
        # Jitter: Sleep between 1.5 and 3.5 seconds to simulate realistic network polling
        time.sleep(random.uniform(1.5, 3.5))

if __name__ == "__main__":
    run_master()
