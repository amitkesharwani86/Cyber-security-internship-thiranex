import socket
from datetime import datetime

# Common ports and services
COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    8080: "HTTP-ALT"
}

open_ports = []

def scan_port(host, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((host, port))

        if result == 0:
            service = COMMON_PORTS.get(port, "Unknown")
            open_ports.append((port, service))

        sock.close()

    except Exception:
        pass


def check_weak_config(port):
    warnings = []

    if port == 21:
        warnings.append("FTP detected. Consider SFTP instead.")

    elif port == 23:
        warnings.append("Telnet detected. Telnet is insecure.")

    elif port == 80:
        warnings.append("HTTP detected. Consider HTTPS.")

    elif port == 3306:
        warnings.append("MySQL exposed to network.")

    return warnings


def generate_report(host):
    report = []
    report.append("=" * 50)
    report.append("VULNERABILITY SCAN REPORT")
    report.append("=" * 50)
    report.append(f"Target: {host}")
    report.append(f"Date: {datetime.now()}")
    report.append("")

    if not open_ports:
        report.append("No open ports found.")
    else:
        report.append("Open Ports:")

        for port, service in open_ports:
            report.append(f"Port {port} -> {service}")

            warnings = check_weak_config(port)

            for warning in warnings:
                report.append(f"  [WARNING] {warning}")

    report.append("")
    report.append("Scan Completed")

    filename = "vulnerability_report.txt"

    with open(filename, "w") as file:
        file.write("\n".join(report))

    return filename


def main():
    host = input("Enter target IP or domain: ")

    print("\nScanning...\n")

    for port in COMMON_PORTS.keys():
        scan_port(host, port)

    print("Scan Finished\n")

    if open_ports:
        print("Open Ports Found:")
        for port, service in open_ports:
            print(f"{port} -> {service}")
    else:
        print("No open ports found.")

    report_file = generate_report(host)

    print(f"\nReport saved as: {report_file}")


if __name__ == "__main__":
    main()