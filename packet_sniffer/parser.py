from scapy.all import time
from models import PacketInfo
from handlers.dhcp_handler import get_dhcp_message_type
from scapy.layers.dot11 import Dot11

def detect_layers(packet):
    network = None
    transport = None
    application = None

    if packet.haslayer(Dot11):
        network = "IEEE 802.11"
    elif packet.haslayer("ARP"):
        network = "ARP"
    elif packet.haslayer("IP"):
        network = "IPv4"
    elif packet.haslayer("IPv6"):
        network = "IPv6"

    if packet.haslayer("ICMP"):
        transport = "ICMP"
    elif packet.haslayer("TCP"):
        transport = "TCP"
    elif packet.haslayer("UDP"):
        transport = "UDP"

    if packet.haslayer("DHCP"):
        application = "DHCP"
    elif packet.haslayer("DNS"):
        application = "DNS"
    
    return network, transport, application

def build_summary(packet):
    if packet.haslayer(Dot11):
        dot11 = packet[Dot11]

        if dot11.type == 0:  # Management
            subtype_map = {
                8: "WiFi Beacon",
                4: "WiFi Probe Request",
                5: "WiFi Probe Response",
                11: "WiFi Authentication",
                0: "WiFi Association Request",
                1: "WiFi Association Response",
            }
            return subtype_map.get(dot11.subtype, "WiFi Management")

        elif dot11.type == 1:
            return "WiFi Control"

        elif dot11.type == 2:
            return "WiFi Data"

    elif packet.haslayer("ARP"):
        op = packet["ARP"].op
        psrc = packet["ARP"].psrc
        pdst = packet["ARP"].pdst

        if psrc == pdst:
            return "ARP gratuitous"
        elif op == 1:
            return "ARP request"
        else:
            return "ARP reply"

    elif packet.haslayer("ICMP"):
        icmp = packet["ICMP"].type
        if icmp == 8:
            return "ICMP echo request"
        elif icmp == 0:
            return "ICMP echo reply"
        
    elif packet.haslayer("DHCP"):
        dhcp_options = packet["DHCP"].options
        dhcp_type = get_dhcp_message_type(dhcp_options)

        match dhcp_type:
            case 1:
                return "DHCP discover"
            case 2:
                return "DHCP offer"
            case 3:
                return "DHCP request"
            case 5:
                return "DHCP ack"
            
            #case 4:
            #    return "DHCP decline"
            #case 6:
             #   return "DHCP nack"
            #case 7: 
             #   return "DHCP release"
            #case 8:
             #   return "DHCP inform"

    elif packet.haslayer("DNS"):
        if packet["DNS"].qr == 0:
            return "DNS query"
        else:
            return "DNS response"
    
    elif packet.haslayer("TCP"):
        flags = str(packet["TCP"].flags)

        if flags == "S":
            return "TCP SYN"
        elif flags == "SA":
            return "TCP SYN-ACK"
        elif flags == "A":
            return "TCP ACK"
        elif "F" in flags:
            return "TCP FIN"
        elif "R" in flags:
            return "TCP RST"
        
    elif packet.haslayer("UDP"):
        return "UDP"

    elif packet.haslayer("IP"):
        return "IPv4"
        
    elif packet.haslayer("IPv6"):
        return "IPv6"

    return "Unknown packet"

def parse_packet(packet, interface):
    network, transport, application = detect_layers(packet)
    top_protocol = application or transport or network or "OTHER"

    info = PacketInfo(
        timestamp = packet.time,
        interface = interface,
        top_protocol = top_protocol,
        size = len(packet),
        summary = build_summary(packet)
    )

    # MAC
    if packet.haslayer("Ether"):
        info.src_mac = packet["Ether"].src
        info.dst_mac = packet["Ether"].dst
    
    elif packet.haslayer(Dot11):
        dot11 = packet[Dot11]

        info.src_mac = dot11.addr2 if dot11.addr2 else None
        info.dst_mac = dot11.addr1 if dot11.addr1 else None

    # IP
    if packet.haslayer("ARP"):
        info.src_ip = packet["ARP"].psrc
        info.dst_ip = packet["ARP"].pdst

    elif packet.haslayer("IP"):
        info.src_ip = packet["IP"].src
        info.dst_ip = packet["IP"].dst
    
    elif packet.haslayer("IPv6"):
        info.src_ip = packet["IPv6"].src
        info.dst_ip = packet["IPv6"].dst

    return info