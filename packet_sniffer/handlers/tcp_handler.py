from scapy.layers.inet import TCP 

tcp_flows = {} #conexões em progresso
tcp_connections = [] #conexões completas

"""
TCP -> processo de criar uma ligação TCP entre dois hosts

TCP SYN -> "quero iniciar uma ligação contigo"
TCP SYN-ACK -> "recebi o pedido e aceito"
TCP ACK -> "confirmação recebida - ligação estabelecida"
FIN -> terminar ligação corretamente
RST -> abortar ligação
"""

tcp_stats = {
    "syn": 0,
    "syn_ack": 0,
    "ack": 0,
    "fin": 0, 
    "rst": 0, 
    "established": 0,
    "rtts": []
}

def handle_tcp(packet,info):
    tcp = packet[TCP]   
    flags = tcp.flags   

    key = (info.src_ip, tcp.sport, info.dst_ip, tcp.dport)
    reverse_key = (info.dst_ip, tcp.dport, info.src_ip, tcp.sport)

    # SYN (início da ligação)
    if flags == "S":
        tcp_stats["syn"] += 1
        tcp_flows[key] = {
            "syn": info
        }

    # SYN-ACK (resposta)
    elif flags == "SA":
        tcp_stats["syn_ack"] += 1

        if reverse_key in tcp_flows:
            tcp_flows[reverse_key]["syn_ack"] = info

    # ACK (final do handshake)
    elif flags == "A" and key in tcp_flows and "syn_ack" in tcp_flows[key]:
        tcp_stats["ack"] += 1

        
        syn = tcp_flows[key]["syn"]
        syn_ack = tcp_flows[key]["syn_ack"]

        rtt_ms = (syn_ack.timestamp - syn.timestamp) * 1000
        tcp_stats["rtts"].append(rtt_ms)

        tcp_connections.append({
            "id": len(tcp_connections) + 1,
            "src": info.src_ip,
            "dst": info.dst_ip,
            "sport": tcp.sport,
            "dport": tcp.dport,
            "rtt": rtt_ms
        })

        tcp_stats["established"] += 1

        del tcp_flows[key]
    
    # FIN
    elif "F" in flags:
        tcp_stats["fin"] += 1

        if key in tcp_flows:
            del tcp_flows[key]
        elif reverse_key in tcp_flows:
            del tcp_flows[reverse_key]

    #RST
    elif "R" in flags:
        tcp_stats["rst"] += 1

        if key in tcp_flows:
            del tcp_flows[key]
        elif reverse_key in tcp_flows:
            del tcp_flows[reverse_key]



def print_tcp_connections():
    for conn in tcp_connections:
        print(f"TCP Connection #{conn['id']}")
        print(f"  {conn['src']}:{conn['sport']} → {conn['dst']}:{conn['dport']}")
        print(f"  RTT: {conn['rtt']:.3f} ms")
        print("-" * 50)

def tcp_summary(): 
    print(f"SYN: {tcp_stats['syn']}") 
    print(f"SYN-ACK: {tcp_stats['syn_ack']}") 
    print(f"ACK: {tcp_stats['ack']}") 
    print(f"Established: {tcp_stats['established']}") 
    print(f"FIN: {tcp_stats['fin']}") 
    print(f"RST: {tcp_stats['rst']}") 
    
    if tcp_stats["rtts"]: 
        avg = sum(tcp_stats["rtts"]) / len(tcp_stats["rtts"]) 
        print(f"RTT avg: {avg:.3f} ms")