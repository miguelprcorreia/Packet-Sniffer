from dataclasses import dataclass
from typing import Optional

# struct destinada a cada pacote
@dataclass
class PacketInfo:
    timestamp: float
    interface: str

    top_protocol: str  # ARP, IPv4, ICMP, DHCP...

    src_mac: Optional[str] = None
    dst_mac: Optional[str] = None

    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None

    size: int = 0

    summary: str = ""  # "ARP request", "ICMP echo request", etc.