import sys
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Missing UI formatting variables from your previous error log
DATA_TAB_1 = '\t - '
DATA_TAB_2 = '\t\t - '
DATA_TAB_3 = '\t\t\t - '
DATA_TAB_4 = '\t\t\t\t - '

def format_multi_line(prefix, string, size=80):
    """Formats raw payload strings/bytes into structured, multi-line chunks."""
    size -= len(prefix)
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    return '\n'.join([prefix + string[i:i+size] for i in range(0, len(string), size)])

def process_packet(packet):
    """Callback function triggered automatically by Scapy for every captured packet."""
    # Windows Scapy handles layer 2 (Ethernet). Let's see if it has an IP layer (Layer 3)
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        print('\n[*] IPv4 Packet Captured:')
        print(f"{DATA_TAB_1}Version: {ip_layer.version}, Header Length: {ip_layer.ihl * 4} bytes")
        print(f"{DATA_TAB_1}TTL: {ip_layer.ttl}, Protocol: {ip_layer.proto}")
        print(f"{DATA_TAB_1}Source IP: {ip_layer.src} -> Destination IP: {ip_layer.dst}")

        # Check for Transport Layer: TCP (Protocol 6)
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            print(f"{DATA_TAB_2}TCP Segment:")
            print(f"{DATA_TAB_3}Source Port: {tcp_layer.sport}, Destination Port: {tcp_layer.dport}")
            print(f"{DATA_TAB_3}Sequence Number: {tcp_layer.seq}, Acknowledgment: {tcp_layer.ack}")
            
            # Extract raw string data payload if present
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                print(f"{DATA_TAB_3}Data Payload:")
                print(format_multi_line(DATA_TAB_4, payload))

        # Check for Transport Layer: UDP (Protocol 17)
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            print(f"{DATA_TAB_2}UDP Segment:")
            print(f"{DATA_TAB_3}Source Port: {udp_layer.sport}, Destination Port: {udp_layer.dport}")
            print(f"{DATA_TAB_3}Length: {udp_layer.len}")
            
            if packet.haslayer('Raw'):
                payload = packet['Raw'].load
                print(f"{DATA_TAB_3}Data Payload:")
                print(format_multi_line(DATA_TAB_4, payload))

        # Check for Network Layer Control: ICMP (Protocol 1)
        elif packet.haslayer(ICMP):
            icmp_layer = packet[ICMP]
            print(f"{DATA_TAB_2}ICMP Packet:")
            print(f"{DATA_TAB_3}Type: {icmp_layer.type}, Code: {icmp_layer.code}")

def main():
    print("[+] Initializing Windows Network Sniffer...")
    print("[*] Monitoring traffic... Press Ctrl+C to stop.\n")
    
    try:
        # sniff loop runs endlessly, capturing packets and routing them to process_packet
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\n[-] Sniffer stopped by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()
