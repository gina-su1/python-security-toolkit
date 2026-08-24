import socket
import sys

services = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3389: "RDP"
}

security_rules = {
    "Telnet": {
        "severity": "HIGH",
        "finding": "Telnet service exposed",
        "recommendation": "Replace Telnet with SSH because Telnet does not provide encrypted communication."
    }
}

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

def enumerate_service(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)

    try:
        sock.connect((target, port))
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        response = sock.recv(4096).decode()

        if "HTTP/" in response:
            service = "HTTP"
        else:
            service = "Unknown"

        banner = None

        for line in response.splitlines():
            if line.startswith("Server:"):
                banner = line.split(":", 1)[1].strip()
                break

        return {
            "service": service,
            "banner": banner
        }

    except (ConnectionRefusedError, socket.timeout):
        return None

    finally:
        sock.close()

def analyze_security(result):
    if result["status"] != "OPEN":
        return None

    service = result["service"]
    rule = security_rules.get(service)

    if rule:
        return rule

    return None

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
security_findings = []

for port in ports:
    result = scan_port(target, port)

    if result == "OPEN":
        service_info = enumerate_service(target, port)

        if service_info:
            service = service_info["service"]
            banner = service_info["banner"]
        else:
            service = services.get(port, "Unknown")
            banner = None
    else:
        service = None
        banner = None

    scan_result = {
        "port": port,
        "status": result,
        "service": service,
        "banner": banner
    }

    finding = analyze_security(scan_result)

    scan_result["finding"] = finding
    results.append(scan_result)

    if finding:
        security_findings.append(scan_result)

    if result == "OPEN":
        print(f"Port {port}: OPEN (Service: {service})")

        if banner:
            print(f"  Banner: {banner}")

        if finding:
            print(f"  Security Finding: {finding['finding']}")
            print(f"  Severity: {finding['severity']}")
            print(f"  Recommendation: {finding['recommendation']}")
    else:
        print(f"Port {port}: {result}")

print("\nOpen ports:")

found_open_port = False

for result in results:
    if result["status"] == "OPEN":
        print(result["port"])
        found_open_port = True

if not found_open_port:
    print("None detected")

print("\nSecurity Findings:")

if not security_findings:
    print("None detected")
else:
    for result in security_findings:
        finding = result["finding"]

        print(f"\nPort {result['port']} - {result['service']}")
        print(f"Severity: {finding['severity']}")
        print(f"Finding: {finding['finding']}")
        print(f"Recommendation: {finding['recommendation']}")



