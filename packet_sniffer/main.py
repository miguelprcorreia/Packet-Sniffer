import argparse

from sniffer import start_sniffing, packets
from analysis import analysis_mode

def get_args():
    parser = argparse.ArgumentParser(description="Packet Sniffer")

    parser.add_argument("-i", "--interface", required=True)
    parser.add_argument("-m", "--mode", default="live", choices=["live", "log", "both"])
    parser.add_argument("-o", "--output", default=None)
    parser.add_argument("-v", "--verbosity",default="verbose",choices=["verbose", "compact"])

    return parser.parse_args()

def main():
    args = get_args()

    print("=== Packet Sniffer Started ===")
    print(f"Interface: {args.interface}")
    print(f"Mode: {args.mode}")
    print(f"Output: {args.output}")

    start_sniffing(
        interface=args.interface,
        mode=args.mode,
        log_path=args.output, 
        verbosity=args.verbosity
    )

    # depois da captura vem para o modo de análise
    print("=== Analysis Mode Started ===")
    analysis_mode(packets)

if __name__ == "__main__":
    main()