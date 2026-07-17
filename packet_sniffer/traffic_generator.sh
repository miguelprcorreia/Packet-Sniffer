#!/bin/bash

# ==============================
# CONFIG
# ==============================

TARGET="10.0.1.20"   # IP do João
PORT=1234

echo "=== AUTO TRAFFIC GENERATOR STARTED ==="
echo "Target: $TARGET"

# ==============================
# FUNÇÕES
# ==============================

generate_arp() {
    echo "[ARP] forcing ARP..."
    ip neigh flush dev eth0 2>/dev/null
    sleep 1
    ping -c 1 $TARGET > /dev/null
}

generate_icmp() {
    echo "[ICMP] ping..."
    ping -c 3 $TARGET > /dev/null
}

generate_tcp() {
    echo "[TCP] sending data..."
    echo "hello $(date)" | nc -w 1 $TARGET $PORT 2>/dev/null
}

generate_udp() {
    echo "[UDP] sending packet..."
    echo "udp test" | nc -u -w 1 $TARGET $PORT 2>/dev/null
}

generate_dns() {
    echo "[DNS] resolving..."
    nslookup google.com > /dev/null
}

generate_http() {
    echo "[HTTP] request..."
    curl http://$TARGET:8000 > /dev/null 2>&1
}

generate_fragments() {
    echo "[IPv4] Generating fragments (MTU bypass)..."
    # -s 3000 cria um payload grande, forçando a divisão em pelo menos 3 fragmentos
    ping -c 1 -s 3000 $TARGET > /dev/null
}

# ==============================
# MAIN LOOP
# ==============================

while true
do
    generate_arp
    sleep 1

    generate_icmp
    sleep 1

    generate_dns
    sleep 1

    generate_tcp
    sleep 1

    generate_udp
    sleep 1

    generate_http
    sleep 2

    generate_fragments
    sleep 1
done

# ==============================
# correr no João
# ==============================
# TCP server:
# while true; do nc -l 1234; done
#
# HTTP server:
# python3 -m http.server 8000
# ==============================