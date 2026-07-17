def filter_by_protocol(packets, proto):
    proto = proto.upper()

    return [
        p for p in packets
        if (
            p.top_protocol.upper() == proto
            or (proto == "IPV4" and hasattr(p, "src_ip") and p.src_ip and "." in p.src_ip)
            or (proto == "IPV6" and hasattr(p, "src_ip") and p.src_ip and ":" in p.src_ip)
        )
    ]

def filter_by_ip(packets, ip):
    return [
        p for p in packets
        if p.src_ip == ip or p.dst_ip == ip
    ]


def filter_by_mac(packets, mac):
    return [
        p for p in packets
        if p.src_mac == mac or p.dst_mac == mac
    ]

