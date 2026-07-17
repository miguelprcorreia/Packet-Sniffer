from datetime import datetime

def format_packet(info, verbosity="verbose"):
    timestamp = datetime.fromtimestamp(info.timestamp).strftime("%H:%M:%S.%f")[:-3]

    if verbosity == "compact":
        src = info.src_ip or info.src_mac or "-"
        dst = info.dst_ip or info.dst_mac or "-"

        # Adicionar portas quando existirem
        if getattr(info, "src_port", None):
            src = f"{src}:{info.src_port}"
        if getattr(info, "dst_port", None):
            dst = f"{dst}:{info.dst_port}"

        # Resumos curtos
        summary_map = {
            "ICMP echo request": "Echo Req",
            "ICMP echo reply": "Echo Rep",
            "ARP request": "ARP Req",
            "ARP reply": "ARP Rep",
            "TCP SYN": "SYN",
            "TCP SYN-ACK": "SYN-ACK",
            "TCP ACK": "ACK",
        }

        short_summary = summary_map.get(info.summary, info.summary[:12])

        return (
            f"[{timestamp}] "
            f"{info.top_protocol:<5} | "
            f"{src:<24} → {dst:<24} | "
            f"{short_summary:<12} | "
            f"{info.size:>5}B"
        )

    # verbose
    return (
        f"[{timestamp}] "
        f"{info.interface:<5} | "
        f"{info.top_protocol:<12} | "
        f"{info.src_mac or '-'} -> {info.dst_mac or '-'} | "
        f"{info.src_ip or '-'} -> {info.dst_ip or '-'} | "
        f"{info.size} bytes | "
        f"{info.summary}"
    )