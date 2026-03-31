import datetime
import os
import sys

import scapy.all as scapy
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether


class Colors:
    BLUE = "\033[94m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    END = "\033[0m"
    BOLD = "\033[1m"


def get_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")


def process_packet(packet):
    print(f"\n{Colors.BOLD}PACKET #{process_packet.count}{Colors.END}")
    process_packet.count += 1

    print(f"Timestamp: {get_timestamp()}")

    if packet.haslayer(Ether):
        eth = packet.getlayer(Ether)
        print(
            f"Ethernet Frame: Source MAC: {eth.src} Destination MAC: {eth.dst} Protocol: {eth.type}"
        )

    if packet.haslayer(IP):
        ip = packet.getlayer(IP)
        print(
            f"IP Header: Version: {ip.version} Header Length: {ip.ihl} TTL: {ip.ttl} Protocol: {ip.proto}"
        )
        print(f"Source IP: {ip.src} Destination IP: {ip.dst}")

        if packet.haslayer(TCP):
            tcp = packet.getlayer(TCP)
            print(f"TCP Header: Source Port: {tcp.sport} Destination Port: {tcp.dport}")
            print(f"Flags: {tcp.flags} Acknowledgment: {tcp.ack}")

            if tcp.dport == 80 or tcp.sport == 80:
                print(f"{Colors.YELLOW}[HTTP Traffic Detected]{Colors.END}")
            elif tcp.dport == 443 or tcp.sport == 443:
                print(f"{Colors.BLUE}[HTTPS Traffic Detected]{Colors.END}")

        elif packet.haslayer(UDP):
            udp = packet.getlayer(UDP)
            print(f"UDP Header: Source Port: {udp.sport} Destination Port: {udp.dport}")
            print(f"Packet Length: {len(packet)}")

            if udp.dport == 53 or udp.sport == 53:
                print(f"{Colors.GREEN}[DNS Query Detected]{Colors.END}")

        elif packet.haslayer(ICMP):
            print(f"{Colors.RED}[ICMP Ping Traffic Detected]{Colors.END}")

    # --- Raw Payload (First 50 bytes) ---
    if packet.haslayer(scapy.Raw):
        payload = packet.getlayer(scapy.Raw).load
        print(f"Raw Payload (First 50 bytes): {payload[:50]}")
        try:
            decoded = payload[:50].decode("utf-8", errors="ignore")
            print(f"Text Decoding Attempt: {decoded}")
        except:
            print("Text Decoding Attempt: [Unable to decode]")

    print(f"Packet Size: {len(packet)} bytes")
    print("-" * 50)


process_packet.count = 1


def list_interfaces():
    print(f"\n{Colors.BOLD}Available Network Interfaces:{Colors.END}")
    scapy.show_interfaces()


def start_sniffing(iface=None):
    print(f"\n{Colors.GREEN}[*] Starting Sniffer... Press Ctrl+C to stop.{Colors.END}")
    try:
        scapy.sniff(iface=iface, prn=process_packet, store=False)
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Sniffing stopped by user.{Colors.END}")
    except PermissionError:
        print(
            f"{Colors.RED}[!] Error: Please run with sudo/Administrator privileges.{Colors.END}"
        )


def main_menu():
    while True:
        print(f"\n{Colors.BOLD}--- Network Sniffer Menu ---{Colors.END}")
        print("1. List network interfaces")
        print("2. Start sniffing (default interface)")
        print("3. Start sniffing (specific interface)")
        print("4. Exit")

        choice = input(f"\n{Colors.BLUE}Select an option: {Colors.END}")

        if choice == "1":
            list_interfaces()
        elif choice == "2":
            start_sniffing()
        elif choice == "3":
            iface = input("Enter interface name (e.g., eth0, wlan0): ")
            start_sniffing(iface)
        elif choice == "4":
            print("Exiting...")
            sys.exit()
        else:
            print(f"{Colors.RED}Invalid option, try again.{Colors.END}")


if __name__ == "__main__":
    if os.name != "nt" and os.geteuid() != 0:
        print(f"{Colors.RED}[!] This script must be run as root/sudo.{Colors.END}")
        sys.exit()
    main_menu()
