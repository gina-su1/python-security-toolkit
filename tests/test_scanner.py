from src.scanner import identify_service, extract_banner, analyze_security, build_report


def test_identify_http():
	assert identify_service("HTTP/1.0 200 OK") == "HTTP"

def test_identify_ssh():
	assert identify_service("SSH-2.0-OpenSSH_9.6") == "SSH"

def test_identify_ftp():
	assert identify_service("220 ftp.example.com FTP") == "FTP"

def test_identify_smtp():
	assert identify_service("220 mail.example.com SMTP") == "SMTP"

def test_identify_unknown():
	assert identify_service("Hello there") == "Unknown"

def test_extract_http_banner():
	response = "HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Python/3.14.5"
	assert extract_banner(response, "HTTP") == "SimpleHTTP/0.6 Python/3.14.5"

def test_extract_ssh_banner():
	response = "SSH-2.0-OpenSSH_9.6"
	assert extract_banner(response, "SSH") == "SSH-2.0-OpenSSH_9.6"

def test_extract_ftp_banner():
	response = "220 ftp.example.com FTP"
	assert extract_banner(response, "FTP") == "220 ftp.example.com FTP"

def test_extract_smtp_banner():
	response = "220 mail.example.com SMTP"
	assert extract_banner(response, "SMTP") == "220 mail.example.com SMTP"

def test_extract_unknown_banner():
	response = "Hello there"
	assert extract_banner(response, "Unknown") is None

def test_analyze_http_security():
	result = {
		"status": "OPEN",
		"service": "HTTP"
	}

	finding = analyze_security(result)

	assert finding["severity"] == "LOW"
	assert finding["finding"] == "Unencrypted HTTP service exposed"

def test_analyze_telnet_security():
	result = {
		"status": "OPEN",
		"service": "Telnet"
	}

	finding = analyze_security(result)

	assert finding["severity"] == "HIGH"
	assert finding["finding"] == "Telnet service exposed"

def test_analyze_ssh_security():
	result = {
		"status": "OPEN",
		"service": "SSH"
	}
	
	finding = analyze_security(result)

	assert finding is None

def test_analyze_closed_port():
	result = {
		"status": "CLOSED",
		"service": "HTTP"
	}

	finding = analyze_security(result)

	assert finding is None

def test_build_report_counts_ports():
	results = [
		{
			"port": 80,
			"status": "OPEN",
			"service": "HTTP",
			"banner": "SimpleHTTP",
			"detection_method": "Service response",
			"finding": {
				"severity": "LOW",
				"finding": "Unencrypted HTTP service exposed",
				"recommendation": "Use HTTPS"
			}
		},
		{
			"port": 81,
			"status": "CLOSED",
			"service": None,
			"banner": None,
			"detection_method": None,
			"finding": None
		}
	]
	
	report = build_report(results, "localhost", "127.0.0.1", "80-81")
	
	assert report["ports_scanned"] == 2
	assert report["open_ports"] == 1
	assert report["security_findings"] == 1

def test_build_report_target_information():
	report = build_report([], "localhost", "127.0.0.1", "80-81")

	assert report["target"] == "localhost"
	assert report["resolved_ip"] == "127.0.0.1"
	assert report["scan_range"] == "80-81"

def test_build_report_contains_scan_time():
	report = build_report([], "localhost", "127.0.0.1", "80-81")
	
	assert "scan_time" in report
