from scapy.all import sniff
from parser import parse_packet
from formatter import format_packet
from handlers.icmp_handler import handle_icmp
from handlers.dhcp_handler import handle_dhcp
from handlers.arp_handler import handle_arp
from handlers.tcp_handler import handle_tcp
from stats import update_protocol_stats,print_protocol_stats,start_timer
from handlers.ipv4_handler import handle_ipv4
from handlers.wifi_handler import handle_wifi

packets = [] # guarda todos os pacotes

def process_packet(packet, interface, mode="live", log_file=None, verbosity="verbose"):
    info = parse_packet(packet, interface)

    if info.summary == "Unknown packet":
        return
    
    packets.append(info)
    update_protocol_stats(packet,info)

    # handlers por protocolo real
    if packet.haslayer("Dot11"):
        handle_wifi(packet, info)

    if packet.haslayer("IP"):
        handle_ipv4(packet, info)

    if packet.haslayer("ICMP"):
        handle_icmp(packet, info)

    if packet.haslayer("ARP"):
        handle_arp(packet, info)

    if packet.haslayer("TCP"):
        handle_tcp(packet, info)

    if packet.haslayer("DHCP"):
        handle_dhcp(packet, info)

    output = format_packet(info, verbosity)

    if mode in ["live", "both"]:
        print(output)

    if mode in ["log", "both"] and log_file:
        log_file.write(output + "\n")

def start_sniffing(interface, mode="live", log_path=None, verbosity="verbose"):
    log_file = open(log_path, "a") if log_path else None

    start_timer()

    try:
        sniff(
            iface=interface,
            prn=lambda pkt: process_packet(pkt, interface, mode, log_file, verbosity),
            store=False
        )
    finally:
        print_protocol_stats()
    