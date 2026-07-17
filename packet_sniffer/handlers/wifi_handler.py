from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11ProbeResp, Dot11Elt

wifi_frames = []

wifi_stats = {
    "management": 0,
    "control": 0,
    "data": 0
}

device_activity = {}
bssid_beacons = {}

def handle_wifi(packet, info):
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    if dot11.type == 0:
        wifi_stats["management"] += 1
    elif dot11.type == 1:
        wifi_stats["control"] += 1
    elif dot11.type == 2:
        wifi_stats["data"] += 1

    # atividade por dispositivo
    src = dot11.addr2
    if src:
        device_activity[src] = device_activity.get(src, 0) + 1

    # beacons (redes WiFi visíveis)
    if dot11.type == 0 and dot11.subtype == 8:
        bssid = dot11.addr3
        if bssid:
            bssid_beacons[bssid] = bssid_beacons.get(bssid, 0) + 1

    # guardar frames 
    frame_info = {
        "timestamp": info.timestamp,
        "type": dot11.type,
        "subtype": dot11.subtype,
        "src": dot11.addr2,
        "dst": dot11.addr1,
        "bssid": dot11.addr3,
        "ssid": None,
    }

    if packet.haslayer(Dot11Elt):
        try:
            frame_info["ssid"] = packet[Dot11Elt].info.decode(errors="ignore")
        except:
            frame_info["ssid"] = "<hidden>"

    wifi_frames.append(frame_info)


def print_wifi_status():
    print("\n=========== WIFI STATUS ===========\n")

    total = sum(wifi_stats.values())

    if total == 0:
        print("[!] No WiFi traffic detected")
        return

    print("Traffic Distribution:")
    for k, v in wifi_stats.items():
        perc = (v / total) * 100
        print(f"  {k:<12}: {v} ({perc:.2f}%)")

    data_ratio = wifi_stats["data"] / total

    print("\nConnection Quality:")
    if data_ratio > 0.6:
        print("  ✔ High (normal usage)")
    elif data_ratio > 0.3:
        print("  ⚠ Medium (mixed traffic)")
    else:
        print("  ✖ Low (mostly scanning / idle)")

    print("\nActive Networks (BSSIDs):")
    if not bssid_beacons:
        print("  None detected")
    else:
        for bssid, count in bssid_beacons.items():
            print(f"  {bssid} -> {count} beacons")

    print("\nTop Devices:")
    top = sorted(device_activity.items(), key=lambda x: x[1], reverse=True)[:5]
    for mac, count in top:
        print(f"  {mac} -> {count} frames")

    print("\n===================================\n")

def print_wifi_analysis():
    if not wifi_frames:
        print("\n[!] No IEEE 802.11 frames captured.")
        return

    frame_types = {
        0: "Management",
        1: "Control",
        2: "Data"
    }

    subtype_names = {
        8: "Beacon",
        4: "Probe Request",
        5: "Probe Response",
        11: "Authentication",
        0: "Association Request",
        1: "Association Response"
    }

    for i, frame in enumerate(wifi_frames, 1):
        frame_type = frame_types.get(frame["type"], str(frame["type"]))
        subtype = subtype_names.get(frame["subtype"], str(frame["subtype"]))

        print(f"Frame #{i:03d}")
        print(f"  Type      : {frame_type}")
        print(f"  Subtype   : {subtype}")
        print(f"  Source    : {frame['src']}")
        print(f"  Destination: {frame['dst']}")
        print(f"  BSSID     : {frame['bssid']}")

        if frame["ssid"] is not None:
            print(f"  SSID      : {frame['ssid'] or '<hidden>'}")

        print("-" * 60)