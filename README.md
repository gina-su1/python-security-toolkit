# Python Security Toolkit

A Python-based network security scanner designed to identify open TCP ports, detect common network services, collect service banners, evaluate basic security risks, and generate structured scan reports.

The project was built to strengthen practical Python, networking, and cybersecurity skills through hands-on development and iterative testing.


## Features

- TCP port scanning across user-defined port ranges
- Command-line target and port-range input
- Hostname and IP address resolution
- Input validation for targets and port ranges
- Common service identification
- Service response-based detection
- Service banner extraction
- Security rule evaluation
- Severity ratings and remediation recommendations
- Human-readable terminal output
- Optional JSON scan reports
- Scan metadata including target, resolved IP, timestamp, and scan statistics
- Automated testing with pytest


## Project Structure

```text
python-security-toolkit/
├── src/
│   ├── __init__.py
│   └── scanner.py
├── tests/
│   └── test_scanner.py
├── docs/
├── reports/
├── .gitignore
├── pytest.ini
├── README.md
└── requirements.txt
```


## Requirements

- Python 3.10 or later
- pytest for running the automated test suite

## Installation

Clone the repository:

```bash
git clone https://github.com/gina-su1/python-security-toolkit.git
cd python-security-toolkit
```

Install the testing dependency:

```bash
python3 -m pip install pytest
```


## Usage

Run the scanner by providing a target and port range:

```bash
python3 src/scanner.py localhost 8080-8080
```

The scanner can also accept an IP address:

```bash
python3 src/scanner.py 127.0.0.1 8080-8080
```

To generate a JSON scan report:

```bash
python3 src/scanner.py localhost 8080-8080 --json
```


## Example Output

```text
Port 8080: OPEN (Service: HTTP)
  Detection: Service response
  Banner: SimpleHTTP/0.6 Python/3.14.5
  Security Finding: Unencrypted HTTP service exposed
  Severity: LOW
  Recommendation: Consider using HTTPS to protect data transmitted between clients and the server.

Open ports:
8080

Security Findings:

Port 8080 - HTTP
Severity: LOW
Finding: Unencrypted HTTP service exposed
Recommendation: Consider using HTTPS to protect data transmitted between clients and the server.
```


## JSON Reporting

The `--json` option generates a structured scan report containing:

- Target hostname or IP address
- Resolved IP address
- Port range scanned
- Scan timestamp
- Number of ports scanned
- Number of open ports
- Number of security findings
- Detailed results for each scanned port

The generated report is saved as `scan_results.json`.



## Security Findings

The scanner currently evaluates several services for basic security risks:

| Service | Severity | Finding |
|---|---|---|
| Telnet | HIGH | Telnet service exposed |
| FTP | MEDIUM | FTP service exposed |
| HTTP | LOW | Unencrypted HTTP service exposed |
| RDP | MEDIUM | Remote Desktop Protocol service exposed |

The scanner provides a security recommendation for each identified finding.


## Testing

The project uses pytest for automated testing.

Run the complete test suite with:

```bash
pytest
```

The test suite covers:

- Service identification
- Service banner extraction
- Security analysis
- Report generation

The current test suite contains 17 automated tests.


## Limitations

This project is intended as a learning and portfolio project and is not intended to replace mature network security tools.

Current limitations include:

- Limited service detection signatures
- Basic TCP connection-based scanning
- Limited banner parsing
- No UDP scanning
- No advanced vulnerability detection
- No parallel scanning
- No operating system fingerprinting


## Future Improvements

Potential future improvements include:

- Expanded service detection
- Additional security rules
- UDP scanning
- Improved banner parsing
- Concurrent port scanning
- More detailed vulnerability checks
- Additional report formats
- Improved command-line argument handling
- Expanded automated test coverage


## Disclaimer

This tool should only be used against systems and networks that you own or have explicit authorization to test.
