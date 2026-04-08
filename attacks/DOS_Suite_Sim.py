import time
import statistics
import random
from pymodbus.client import ModbusTcpClient

TARGET_IP = "10.30.0.3"   # Change if needed
PORT = 5020


def choose_function():
    print("\nSelect Modbus Function:")
    print("1) read_coils")
    print("2) read_discrete_inputs")
    print("3) read_holding_registers")
    print("4) read_input_registers")
    print("5) write_single_coil")
    print("6) write_single_register")

    choice = input("Enter number: ")

    functions = {
        "1": "read_coils",
        "2": "read_discrete_inputs",
        "3": "read_holding_registers",
        "4": "read_input_registers",
        "5": "write_single_coil",
        "6": "write_single_register",
    }

    return functions.get(choice, None)


def send_request(client, function_name):
    address = random.randint(0, 1000)

    if function_name == "read_coils":
        return client.read_coils(address, count=10)

    elif function_name == "read_discrete_inputs":
        return client.read_discrete_inputs(address, count=10)

    elif function_name == "read_holding_registers":
        return client.read_holding_registers(address, count=10)

    elif function_name == "read_input_registers":
        return client.read_input_registers(address, count=10)

    elif function_name == "write_single_coil":
        return client.write_coil(address, value=random.choice([True, False]))

    elif function_name == "write_single_register":
        return client.write_register(address, value=random.randint(0, 65535))


def main():
    function_name = choose_function()
    if not function_name:
        print("Invalid selection.")
        return

    try:
        request_rate = int(input("Requests per second: "))
        duration = int(input("Duration (seconds): "))
    except ValueError:
        print("Invalid number entered.")
        return

    client = ModbusTcpClient(TARGET_IP, port=PORT)

    if not client.connect():
        print("❌ Could not connect to server.")
        return

    print(f"\nConnected to {TARGET_IP}:{PORT}")
    print(f"Function: {function_name}")
    print(f"RPS: {request_rate}")
    print(f"Duration: {duration} seconds\n")

    latencies = []
    errors = 0
    total_requests = 0

    interval = 1 / request_rate
    end_time = time.time() + duration

    while time.time() < end_time:
        start = time.time()

        try:
            response = send_request(client, function_name)

            if response.isError():
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
    print(f"Error Rate: {(errors/total_requests)*100:.2f}%")
    print(f"Average Latency: {statistics.mean(latencies)*1000:.2f} ms")
    print(f"Min Latency: {min(latencies)*1000:.2f} ms")
    print(f"Max Latency: {max(latencies)*1000:.2f} ms")
    print(f"Achieved RPS: {total_requests/duration:.2f}")


if __name__ == "__main__":
    main()
