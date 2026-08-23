import socket
import sys

def scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        sock.connect((target, port))
        status = "OPEN"
    except ConnectionRefusedError:
        status = "CLOSED"
    except socket.timeout:
        status = "TIMEOUT"

    sock.close()

    return status

if len(sys.argv) < 3:
    print("Usage: python3 src/scanner.py <target> <start_port>-<end_port>")
    sys.exit(1)

try:
    target = socket.gethostbyname(sys.argv[1])
except socket.gaierror:
    print("Invalid target. Target must be a valid IP address or resolvable hostname.")
    sys.exit(1)

port_range = sys.argv[2]

if "-" not in port_range:
    print("Invalid port range. Use the format <start>-<end>.")
    sys.exit(1)

start_port, end_port = port_range.split("-")

start_port = int(start_port)
end_port = int(end_port)

if start_port < 1 or end_port > 65535:
    print("Invalid port range. Ports must be between 1 and 65535.")
    sys.exit(1)

if start_port > end_port:
    print("Invalid port range. Start port must be less than or equal to end port.")
    sys.exit(1)

ports = range(start_port, end_port + 1)

results = []

for port in ports:
    result = scan_port(target, port)

    results.append({
        "port": port,
        "status": result
    })

    print(f"Port {port}: {result}")

print("\nOpen ports:")

found_open_port = False

for result in results:
    if result["status"] == "OPEN":
        print(result["port"])
        found_open_port = True

if not found_open_port:
    print("None detected")
