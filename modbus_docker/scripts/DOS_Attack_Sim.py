import argparse
import random
import statistics
import time
from pymodbus.client import ModbusTcpClient


def main():
    parser = argparse.ArgumentParser(description="Modbus/TCP request-rate stress (application-layer DoS sim).")
    parser.add_argument("--target", required=True, help="PLC IP")
    parser.add_argument("--port", type=int, default=5020)
    parser.add_argument("--duration", type=float, default=12.0, help="Seconds to run")
    parser.add_argument("--rps", type=float, default=25.0, help="Target requests per second (approximate)")
    parser.add_argument("--unit", type=int, default=0, help="Modbus unit / slave id")
    args = parser.parse_args()

    if args.rps <= 0 or args.duration <= 0:
        print("duration and rps must be positive")
        return

    client = ModbusTcpClient(args.target, port=args.port)

    if not client.connect():
        print("Could not connect to server.")
        return

    latencies = []
    errors = 0
    total_requests = 0

    interval = 1.0 / args.rps
    end_time = time.time() + args.duration

    while time.time() < end_time:
        start = time.time()

        try:
            rr = client.read_holding_registers(
                address=random.randint(0, 1000),
                count=10,
                slave=args.unit,
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
        print(f"Achieved RPS: {total_requests / args.duration:.2f}")


if __name__ == "__main__":
    main()
