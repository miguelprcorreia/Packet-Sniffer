from scapy.layers.l2 import ARP

# ARP
arp_table = {}       # ip -> last ARP info
arp_pairs = []       # pares request/reply completos
arp_stats = {
    "requests": 0,
    "replies": 0,
    "gratuitous": 0,
    "rtts": []
}

def handle_arp(packet, info):
    arp = packet[ARP]

    # sender IP == target IP (Acontece qnd está a anunciar)
    if arp.psrc == arp.pdst:
        arp_stats["gratuitous"] += 1
        arp_table[arp.psrc] = info
        return

    key = (arp.psrc, arp.pdst)

    # ARP Request (op=1)
    if arp.op == 1:
        arp_stats["requests"] += 1
        arp_table[key] = info

    # ARP Reply (op=2)
    elif arp.op == 2:
        arp_stats["replies"] += 1
        reverse_key = (arp.pdst, arp.psrc)

        if reverse_key in arp_table:
            request = arp_table.pop(reverse_key)
            rtt_ms = (info.timestamp - request.timestamp) * 1000
            arp_stats["rtts"].append(rtt_ms)
            arp_pairs.append({
                "id": len(arp_pairs) + 1,
                "request": request,
                "reply": info,
                "rtt": rtt_ms,
                "who_has": arp.pdst,    # IP perguntado
                "is_at": arp.hwsrc      # MAC respondido
            })
            arp_table[arp.psrc] = info

# Funções de análise

def print_arp_pairs():
    for pair in arp_pairs:
        pid    = pair["id"]
        req    = pair["request"]
        rep    = pair["reply"]
        rtt    = pair["rtt"]
        who    = pair["who_has"]
        is_at  = pair["is_at"]

        print(f"ARP Pair #{pid}")
        print(f"  Request: {req.src_ip} asked  → who has {who}?")
        print(f"  Reply:   {rep.src_ip} answered → {who} is at {is_at}")
        print(f"  RTT:     {rtt:.3f} ms")
        print("-" * 50)


def arp_summary():
    print(f"Requests:   {arp_stats['requests']}")
    print(f"Replies:    {arp_stats['replies']}")
    print(f"Gratuitous: {arp_stats['gratuitous']}")
    if arp_stats["rtts"]:
        avg = sum(arp_stats["rtts"]) / len(arp_stats["rtts"])
        print(f"RTT avg:    {avg:.3f} ms")
        print(f"RTT min:    {min(arp_stats['rtts']):.3f} ms")
        print(f"RTT max:    {max(arp_stats['rtts']):.3f} ms")