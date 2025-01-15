from scapy.all import sniff, IP, TCP, UDP, ICMP

def analyze_packet(packet):
    """
    Callback function to process each captured packet.
    """
    print("\n=== Packet Captured ===")

    # Check if the packet has an IP layer
    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination IP: {ip_layer.dst}")
        print(f"Protocol: {ip_layer.proto}")

        # Check for transport layer protocols
        if TCP in packet:
            print("Transport Protocol: TCP")
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
        elif UDP in packet:
            print("Transport Protocol: UDP")
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
        elif ICMP in packet:
            print("Transport Protocol: ICMP")
    else:
        print("Non-IP packet captured.")

    # Print raw payload (if any)
    if packet.payload:
        print(f"Payload: {bytes(packet.payload).hex()}")

def start_sniffer(interface=None):
    """
    Start the packet sniffer on a specified interface.
    """
    print("Starting packet sniffer...")
    sniff(iface=interface, prn=analyze_packet, store=False)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simple Packet Sniffer Tool")
    parser.add_argument("-i", "--interface", help="Network interface to sniff on (default: all interfaces)", default=None)
    args = parser.parse_args()

    try:
        start_sniffer(interface=args.interface)
    except PermissionError:
        print("Error: Please run the script as an administrator.")
    except KeyboardInterrupt:
        print("\nStopping packet sniffer.")
