from scapy.layers.inet import ICMP

# ICMP
icmp_table = {}
icmp_pairs = []

icmp_stats = {
    "requests": 0,
    "replies": 0,
    "rtts": []
}

def handle_icmp(packet, info):
    icmp = packet[ICMP]

    key = (info.src_ip, info.dst_ip, icmp.id, icmp.seq)

    # Echo Request
    if icmp.type == 8:
        icmp_stats["requests"] += 1
        icmp_table[key] = info

    # Echo Reply
    elif icmp.type == 0:
        icmp_stats["replies"] += 1
        reverse_key = (info.dst_ip, info.src_ip, icmp.id, icmp.seq)

        if reverse_key in icmp_table: # inverte a ordem, e vê se está nos pendentes, se sim adiciona nos pares completos
            request = icmp_table.pop(reverse_key)
            
            rtt_ms = (info.timestamp - request.timestamp) * 1000
            icmp_stats["rtts"].append(rtt_ms)
            
            icmp_pairs.append({
                "id": len(icmp_pairs) + 1,
                "request": request,
                "reply": info,
                "rtt": rtt_ms,
                "icmp_id": icmp.id,
                "icmp_seq": icmp.seq
            })


# Funções de análise

# Mostra o RTT
def print_icmp_pairs():
    for pair in icmp_pairs:
        pid = pair["id"]
        req = pair["request"]
        rep = pair["reply"]
        rtt = pair["rtt"]
        icmp_id = pair["icmp_id"]
        icmp_seq = pair["icmp_seq"]

        print(f"ICMP Echo #{pid} (seq={icmp_seq}, id={icmp_id})")
        print(f"Request: {req.src_ip} → {req.dst_ip}")
        print(f"Reply:   {rep.src_ip} → {rep.dst_ip}")
        print(f"RTT:     {rtt:.3f} ms")
        print("-" * 50)

# Estatísticas do ICMP
def icmp_summary():
    if icmp_stats["rtts"]:
        avg = sum(icmp_stats["rtts"]) / len(icmp_stats["rtts"])
        print(f"RTT avg: {avg:.3f} ms")
        print(f"RTT min: {min(icmp_stats['rtts']):.3f} ms")
        print(f"RTT max: {max(icmp_stats['rtts']):.3f} ms")

    print(f"Requests: {icmp_stats['requests']}")
    print(f"Replies: {icmp_stats['replies']}")