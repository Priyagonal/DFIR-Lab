# Network Traffic Analyzer - DFIR Project (Advanced)

ip_counter = {}
ip_destinations = {}
ip_ports = {}

with open("sample_packets.txt", "r") as file:
    for line in file:
        line = line.strip()

        if "SRC=" in line and "DST=" in line and "PORT=" in line:
            parts = line.split()

            src_ip = ""
            dst_ip = ""
            port = ""

            # Extract values
            for part in parts:
                if part.startswith("SRC="):
                    src_ip = part.split("=")[1]
                elif part.startswith("DST="):
                    dst_ip = part.split("=")[1]
                elif part.startswith("PORT="):
                    port = part.split("=")[1]

            # Count requests
            if src_ip in ip_counter:
                ip_counter[src_ip] += 1
            else:
                ip_counter[src_ip] = 1

            # Track destinations
            if src_ip in ip_destinations:
                ip_destinations[src_ip].add(dst_ip)
            else:
                ip_destinations[src_ip] = {dst_ip}

            # Track ports
            if src_ip in ip_ports:
                ip_ports[src_ip].add(port)
            else:
                ip_ports[src_ip] = {port}

# ---------------- OUTPUT ---------------- #

print("IP Activity:\n")
for ip, count in ip_counter.items():
    print(f"{ip} → {count} packets")

print("\nHigh Activity Alerts:\n")
for ip, count in ip_counter.items():
    if count >= 3:
        print(f"ALERT: {ip} has {count} requests (Possible attack)")

print("\nNetwork Scanning Detection (Multiple Destinations):\n")
for ip, destinations in ip_destinations.items():
    if len(destinations) >= 3:
        print(f"ALERT: {ip} accessed multiple systems {destinations}")

print("\nPort Scanning Detection (Multiple Ports):\n")
for ip, ports in ip_ports.items():
    if len(ports) >= 3:
        print(f"ALERT: {ip} scanned multiple ports {ports}")