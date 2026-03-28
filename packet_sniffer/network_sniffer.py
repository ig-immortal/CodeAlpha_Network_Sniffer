import time
import datetime
ascii_art = r"""
                 _________-----_____
       _____------           __      ----_
___----             ___------              \
   ----________        ----                 \
               -----__    |             _____)
                    __-                /     \
        _______-----    ___--          \    /)\
  ------_______      ---____            \__/  /
               -----__    \ --    _          /\
                      --__--__     \_____/   \_/\
                              ----|   /          |
                                  |  |___________|
                                  |  | ((_(_)| )_)
                                  |  \_((_(_)|/(_)
                                  \             (
                                   \_____________)
"""

# Print in green
print("\033[92m" + ascii_art + "\033[0m")
print("                          \033[1;32mAuth: ig-immortal\033[0m")
from scapy.all import sniff, Ether, IP, TCP, UDP, ICMP, ARP, IPv6

def slow_print(text, delay=0.01):
    """Print text slowly, character by character."""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(delay)
    print()  # move to next line

def process_packet(packet):
    slow_print("=" * 80)
    slow_print(f" Packet Captured at {datetime.datetime.now()}")
    slow_print("=" * 80)

    # Ethernet Layer
    if packet.haslayer(Ether):
        eth_layer = packet[Ether]
        slow_print(f"-> Ethernet: {eth_layer.src} -> {eth_layer.dst} | Type: {hex(eth_layer.type)}")

    # IP Layer (IPv4 & IPv6)
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        slow_print(f" IPv4: {ip_layer.src} -> {ip_layer.dst} | Protocol: {ip_layer.proto} | TTL: {ip_layer.ttl}")
    elif packet.haslayer(IPv6):
        ipv6_layer = packet[IPv6]
        slow_print(f" IPv6: {ipv6_layer.src} -> {ipv6_layer.dst} | Next Header: {ipv6_layer.nh}")

    # TCP Layer
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        slow_print(f" TCP: {tcp_layer.sport} -> {tcp_layer.dport} | Seq: {tcp_layer.seq} | Ack: {tcp_layer.ack} | Flags: {tcp_layer.flags}")

    # UDP Layer
    if packet.haslayer(UDP):
        udp_layer = packet[UDP]
        slow_print(f" UDP: {udp_layer.sport} -> {udp_layer.dport} | Length: {udp_layer.len}")

    # ICMP Layer
    if packet.haslayer(ICMP):
        icmp_layer = packet[ICMP]
        slow_print(f" ICMP: Type={icmp_layer.type} | Code={icmp_layer.code}")

    # ARP Layer
    if packet.haslayer(ARP):
        arp_layer = packet[ARP]
        slow_print(f" ARP: {arp_layer.psrc} -> {arp_layer.pdst} | Opcode: {arp_layer.op}")

    # Raw Data (if exists)
    if packet.haslayer("Raw"):
        raw_data = packet["Raw"].load
        slow_print(f" Raw Data: {raw_data}")

    slow_print("=" * 80)

# Start packet capturing (Run as Administrator)
slow_print(" Network Sniffer Running... Press Ctrl+C to stop.", delay=0.02)
sniff(prn=process_packet, store=False)