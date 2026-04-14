import time
import statistics
import random
from pymodbus.client import ModbusTcpClient

TARGET_IP = "10.30.0.5"   # Change to honeypot IP if needed
PORT = 5020
REQUEST_RATE = 500       # Requests per second
DURATION = 20            # Seconds to run


def main():
    client = ModbusTcpClient(TARGET_IP, port=PORT)

    if not client.connect():
        print("❌ Could not connect to server.")
        return

    latencies = []
    errors = 0
    total_requests = 0

    interval = 1 / REQUEST_RATE
    end_time = time.time() + DURATION

    while time.time() < end_time:
        start = time.time()

        try:
            rr = client.read_holding_registers(
                address=random.randint(0, 1000),
                count=10
            )

            if rr.isError():
                errors += 1

        except Exception:
            errors += 1

        latency = time.time() - start
        latencies.append(latency)
        total_requests += 1

        sleep_time = interval - latency
        if sleep_time > 0:
            time.sleep(sleep_time)

    client.close()

    print("\n--- Test Results ---")
    print(f"Total Requests: {total_requests}")
    print(f"Errors: {errors}")

    if latencies:
        print(f"Average Latency: {statistics.mean(latencies):.6f} sec")
        print(f"Max Latency: {max(latencies):.6f} sec")
        print(f"Achieved RPS: {total_requests / DURATION:.2f}")


if __name__ == "__main__":
    main()
