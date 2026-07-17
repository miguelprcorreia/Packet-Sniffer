from handlers.icmp_handler import print_icmp_pairs,icmp_summary
from filters import filter_by_ip,filter_by_protocol,filter_by_mac
from formatter import format_packet
from handlers.dhcp_handler import process_transactions,print_dhcp_flows
from handlers.arp_handler import print_arp_pairs,  arp_summary 
from handlers.tcp_handler import print_tcp_connections,tcp_summary
from handlers.ipv4_handler import print_packetsInfo,print_fragments
from handlers.wifi_handler import print_wifi_analysis, print_wifi_status

def analysis_mode(packets):
    #faz o pré processamento das transações DHCP
    process_transactions()
    while True:
        cmd = input("[sniffer] > ")

        if cmd.lower() == "icmp":
            print_icmp_pairs()
        
        elif cmd.lower() == "dhcp":
            print_dhcp_flows()
        
        elif cmd.lower() == "arp":
            print_arp_pairs()       #isto é o histórico ()

        elif cmd.lower() == "tcp":
            print_tcp_connections()

        elif cmd.lower() == "ipv4":
            print_packetsInfo()

        elif cmd.lower() == "wifi":
            print_wifi_analysis()

        elif cmd.startswith("status"):
            proto = cmd.split()[1].lower()

            if (proto == "icmp"):
                icmp_summary()

            elif proto == "arp":   
                arp_summary()
            
            elif proto == "tcp":
                tcp_summary()

            elif proto == "wifi":
                print_wifi_status()

        elif cmd.startswith("fragments"):
            proto = cmd.split()[1].lower()

            if (proto == "ipv4"):
                print_fragments()

        elif cmd.startswith("filter ip"):
            ip = cmd.split()[2]
            res = filter_by_ip(packets, ip)
            for p in res:
                print(format_packet(p))

        elif cmd.startswith("filter proto"):
            proto = cmd.split()[2].upper()
            res = filter_by_protocol(packets, proto)
            for p in res:
                print(format_packet(p))

        elif cmd.startswith("filter mac"):
            mac = cmd.split()[2]
            res = filter_by_mac(packets,mac)
            for p in res:
                print(format_packet(p))

        elif cmd == "exit":
            break
