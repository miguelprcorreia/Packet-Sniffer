from scapy.layers.dhcp import BOOTP

#DHCP

#Hash table xid -> mensagens DHCP da transação xid
dhcp_transactions = {}

def handle_dhcp(packet, info):
    dhcp = packet[BOOTP]
    key = dhcp.xid

    if key not in dhcp_transactions:
        dhcp_transactions[key] = []

    dhcp_transactions[key].append(info)

def print_dhcp_flows():
    print("\n=== DHCP Flows (per XID) ===\n")

    for xid, packets in dhcp_transactions.items():
        print(f"DHCP Transaction XID: {xid}")

        # ordenar por tempo
        packets_sorted = sorted(packets, key=lambda p: p.timestamp)

        if not packets_sorted:
            continue

        base_time = packets_sorted[0].timestamp

        for p in packets_sorted:
            rel_time = (p.timestamp - base_time) * 1000  # ms

            print(f"[{rel_time:8.2f} ms] "
                  f"{p.summary:<15} | "
                  f"{p.src_ip} → {p.dst_ip} | "
                  f"{p.src_mac} → {p.dst_mac}")

        print("-" * 70)

def get_dhcp_message_type(options):
    for opt in options:
        if opt[0] == 'message-type':
            return opt[1]
    return None