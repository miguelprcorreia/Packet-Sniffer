import time

protocol_stats = {}
start_time = None
total_bytes_global = 0
total_packets_global = 0

def format_bytes(size):
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if size < 1024:
            return f"{size:.2f} {unit}"
        size /= 1024

def start_timer():
    global start_time
    if start_time is None:
        start_time = time.time()

def update_protocol_stats(packet, info):
    global protocol_stats, total_bytes_global, total_packets_global

    total_bytes_global += info.size
    total_packets_global += 1

    def add(proto):
        if proto not in protocol_stats:
            protocol_stats[proto] = {"packets": 0, "bytes": 0}

        protocol_stats[proto]["packets"] += 1
        protocol_stats[proto]["bytes"] += info.size

    if packet.haslayer("IP"):
        add("IPv4")

    if packet.haslayer("IPv6"):
        add("IPv6")

    if packet.haslayer("Dot11"):
        add("IEEE 802.11")

    if packet.haslayer("ICMP"):
        add("ICMP")

    if packet.haslayer("TCP"):
        add("TCP")

    if packet.haslayer("UDP"):
        add("UDP")

    if packet.haslayer("DNS"):
        add("DNS")

    if packet.haslayer("DHCP"):
        add("DHCP")

    if packet.haslayer("ARP"):
        add("ARP")

def print_protocol_stats():
    elapsed_time = time.time() - start_time if start_time else 0
    total_rate = total_bytes_global / elapsed_time if elapsed_time > 0 else 0

    print("\n=== Protocol Statistics ===")
    print(f"Total Traffic: {format_bytes(total_bytes_global)}")
    print(f"Average Rate: {format_bytes(total_rate)}/s\n")

    print(f"{'PROTO':<15} {'%':>8} {'BYTES':>15} {'PACKETS':>10} {'RATE':>15}")
    print("-" * 80)

    for proto, data in sorted(protocol_stats.items(), key=lambda x: x[1]["bytes"], reverse=True):
        percent = (data["bytes"] / total_bytes_global) * 100 if total_bytes_global > 0 else 0
        rate = data["bytes"] / elapsed_time if elapsed_time > 0 else 0

        print(
            f"{proto:<15} "
            f"{percent:>7.2f}% "
            f"{format_bytes(data['bytes']):>15} "
            f"{data['packets']:>10} "
            f"{format_bytes(rate) + '/s':>15}"
        )