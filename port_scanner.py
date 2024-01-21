import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            s.connect((ip, port))
            return True
    except (socket.timeout, socket.error):
        return False

def scan_ip(ip, ports):
    open_ports = []
    for port in ports:
        if scan_port(ip, port):
            open_ports.append(port)
    return open_ports

def main():
    target = input("Enter target IP address or range (e.g., 192.168.1.1 or 192.168.1.1-10): ")
    target_ip_list = [str(ip) for ip in ipaddress.IPv4Network(target, strict=False)]
    
    # You can customize the range of ports to scan
    ports_to_scan = range(1, 1025)  # Common ports range from 1 to 1024

    with ThreadPoolExecutor() as executor:
        results = executor.map(lambda ip: scan_ip(ip, ports_to_scan), target_ip_list)

    for ip, open_ports in zip(target_ip_list, results):
        if open_ports:
            print(f"Open ports on {ip}: {', '.join(map(str, open_ports))}")
        else:
            print(f"No open ports on {ip}")

if __name__ == "__main__":
    main()
