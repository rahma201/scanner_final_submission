import socket
import ipaddress
from concurrent.futures import ThreadPoolExecutor


COMMON_PORTS = [
    21,   # FTP
    22,   # SSH
    23,   # Telnet
    25,   # SMTP
    53,   # DNS
    80,   # HTTP
    110,  # POP3
    139,  # NetBIOS
    143,  # IMAP
    443,  # HTTPS
    445,  # SMB
    3389  # RDP
]

#Simple TCP ping using port 80
def is_host_alive(ip, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), 80))
        sock.close()
        return result == 0
    except:
        return False

#Check if single port is open
def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        return result == 0
    except:
        return False

#Scan one host
def scan_target(ip):
    open_ports = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = {
            executor.submit(scan_port, ip, port): port
            for port in COMMON_PORTS
        }
        for future in futures:
            port = futures[future]
            if future.result():
                open_ports.append(port)
    return {
        "ip": str(ip),
        "open_ports": open_ports
    }

#Handle single IP or CIDR
def parse_targets(target_input):
    targets = []
    try:
        if "/" in target_input:
            network = ipaddress.ip_network(target_input, strict=False)
            targets = [str(ip) for ip in network.hosts()]
        else:
            targets = [target_input]
    except ValueError:
        print("Invalid IP or CIDR format.")
    return targets

#Main scanning function
def run_scan(target_input):
    results = {}
    targets = parse_targets(target_input)
    for target in targets:
        print(f"[+] Scanning {target} ...")
        result = scan_target(target)
        if result["open_ports"]:
            results[target] = result
        else:
            results[target] = {
                "ip": target,
                "open_ports": []
            }
    return results
