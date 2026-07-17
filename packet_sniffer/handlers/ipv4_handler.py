from scapy.layers.inet import IP
from datetime import datetime

#Hash table (id) -> fragmentos IPv4 com esse id   
ipv4_fragments = {}

ipv4_packetsInfo = []

def handle_ipv4(packet, info):
    ipv4 = packet[IP]
    key = ipv4.id

     # Flags
    mf = int(ipv4.flags) & 0x1
    is_fragment = (ipv4.frag > 0) or (mf == 1)

    # Apenas guardar fragmentos
    if is_fragment:
        if key not in ipv4_fragments:
            ipv4_fragments[key] = []
    
        ipv4_fragments[key].append((ipv4, info))

    # guardar todos para análise geral
    ipv4_packetsInfo.append((ipv4, info))


def print_packetsInfo():
    print(f"\n{'='*25} IPv4 PACKETS ANALYSIS {'='*25}\n")

    proto_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }
    
    for i, (ip, info) in enumerate(ipv4_packetsInfo):
        # Tradução do protocolo
        proto_name = proto_map.get(ip.proto, str(ip.proto))
        
        # Extração manual das flags (bits)
        # O Scapy armazena flags como um FlagValue, mas podemos converter para inteiro
        f_val = int(ip.flags)
        res = (f_val >> 2) & 0x1  # Bit de reserva
        df = (f_val >> 1) & 0x1   # Don't Fragment
        mf = f_val & 0x1          # More Fragments

        print(f"Packet #{i+1:03d}")
        print(f"  Route:       {ip.src} -> {ip.dst}")
        print(f"  Protocol:    {proto_name} (Number: {ip.proto})")
        print(f"  ID:          {ip.id:<8} | Frag Offset: {ip.frag}")
        
        # Exibição detalhada das Flags
        print(f"  Flags:       [MF={mf}, DF={df}, Res={res}]")
        
        print(f"  TTL:         {ip.ttl:<8} | Total Len: {ip.len:<5} | IHL: {ip.ihl}")
        print(f"  Checksum:    {hex(ip.chksum)}")

        timestamp = datetime.fromtimestamp(info.timestamp).strftime("%H:%M:%S.%f")[:-3]

        print(f"Timestamp: {timestamp}")

        
        if ip.options:
            print(f"  Options:     {ip.options}")
            
        print("-" * 70)

def print_fragments():
    print(f"\n{'='*20} IPv4 FRAGMENTATION GROUPS {'='*20}")

    proto_map = {
        1: "ICMP",
        6: "TCP",
        17: "UDP"
    }

    found = False

    for id, frags in ipv4_fragments.items():

        frags_sorted = sorted(frags, key=lambda x: x[0].frag)
        first_ip = frags_sorted[0][0]

        found = True

        src = first_ip.src
        dst = first_ip.dst
        proto = first_ip.proto

        proto_name = proto_map.get(proto, str(proto))

        print(f"\nDatagram ID: {id} | {src} -> {dst} | Protocol: {proto_name}")

        start_time = frags_sorted[0][1].timestamp
        total_payload = 0
        is_complete = False

        for idx, (f, f_info) in enumerate(frags_sorted):
            mf = int(f.flags) & 0x1
            real_offset = f.frag * 8

            payload_len = f.len - (f.ihl * 4)
            total_payload += payload_len

            rel_time = (f_info.timestamp - start_time) * 1000

            if mf == 0:
                is_complete = True

            print(
                f"  [{idx+1}] Offset: {real_offset:<5} | "
                f"Time: +{rel_time:7.2f}ms | "
                f"Size: {payload_len:<4} | MF: {mf}"
            )

        status = "COMPLETE" if is_complete else "INCOMPLETE"

        print(
            f"  Summary: {len(frags)} fragments | "
            f"Total Payload: {total_payload} bytes | Status: {status}"
        )
        print("-" * 75)

    if not found:
        print("[!] No fragmented packets found.")

"""
def print_fragments():
    print(f"\n{'='*20} IPv4 FRAGMENTATION GROUPS {'='*20}")
    
    # Percorre a hashtable original diretamente
    for xid, frags in ipv4_fragments.items():
        
        # Filtro: Só processa se houver mais de um fragmento ou se o único pacote tiver MF=1 ou Offset > 0
        # frags[0][0] acessa o primeiro pacote da lista de tuplas
        first_ip = frags[0][0]

        print(f"\nDatagram ID: {xid}")
        
        # Ordenação imediata para garantir a sequência correta dos dados
        frags_sorted = sorted(frags, key=lambda x: x[0].frag)
        
        start_time = frags_sorted[0][1].timestamp
        total_data_len = 0
        is_complete = False
        
        for idx, (f, f_info) in enumerate(frags_sorted):
            f_val = int(f.flags)
            mf = f_val & 0x1
            
            # Cálculo de dados
            payload_len = f.len - (f.ihl * 4)
            total_data_len += payload_len
            
            # Tempo relativo à chegada do primeiro fragmento
            rel_time = (f_info.timestamp - start_time) * 1000 # ms
            
            if mf == 0:
                is_complete = True

            print(f"  [{idx+1}] Offset: {f.frag:<5} | Time: +{rel_time:7.2f}ms | Size: {payload_len:<4} | MF: {mf} | Proto: {f.payload.name}")

        status = "COMPLETE" if is_complete else "INCOMPLETE/LEAKING"
        print(f"  Summary: {len(frags)} fragments | Total Payload: {total_data_len} bytes | Status: {status}")
        print("-" * 75)
"""