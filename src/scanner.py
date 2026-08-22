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

if len(sys.argv) < 2:
    print("Usage: python3 src/scanner.py <target>")
    sys.exit(1)

target = sys.argv[1]
ports = [22, 23, 25, 53, 80, 443, 8080]

for port in ports:
    result = scan_port(target, port)
    print(f"Port {port}: {result}")
