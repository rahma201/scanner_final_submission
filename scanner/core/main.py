from port_scanner import run_scan

if __name__ == "__main__":
    target = input("Enter target IP or CIDR: ")
    results = run_scan(target)

    print("\n=== Scan Results ===")
    for ip, data in results.items():
        print(f"\nTarget: {ip}")
        if data["open_ports"]:
            for port in data["open_ports"]:
                print(f"  [+] Port {port} OPEN")
        else:
            print("  [-] No open common ports found")
