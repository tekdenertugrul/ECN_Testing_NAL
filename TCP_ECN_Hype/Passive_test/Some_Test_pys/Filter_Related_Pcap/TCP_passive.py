from scapy.all import rdpcap, TCP, IP, IPv6, Ether

# Load the pcap file
packets = rdpcap('/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/First_Try_With_1K/40_mins_EPFL_Network_Trace.pcapng')

# Update this path to a valid location on your system
tcp_packets_file = '/Users/ertugrulgazitekden/Desktop/40mins_tcp_packets_headers.txt'

def format_packet(packet):
    # Extract the layers
    layers = "Ether / IP / TCP" if IP in packet else "Ether / IPv6 / TCP"
    # Source and destination
    src = packet[IP].src if IP in packet else packet[IPv6].src
    dst = packet[IP].dst if IP in packet else packet[IPv6].dst
    sport = packet[TCP].sport
    dport = packet[TCP].dport
    # TCP flags
    flags = packet[TCP].sprintf("%TCP.flags%")
    # ECN info
    ip_ecn = (packet[IP].tos & 0b11) if IP in packet else (packet[IPv6].tc & 0b11)
    tcp_ece = packet[TCP].flags.E
    tcp_cwr = packet[TCP].flags.C
    return f"{layers} {src}:{sport} > {dst}:{dport} {flags}, IP ECN: {ip_ecn}, TCP ECE: {'True' if tcp_ece else 'False'}, TCP CWR: {'True' if tcp_cwr else 'False'}"

# Function to save TCP packets in the desired format
def save_tcp_packets(packets, tcp_packets_file):
    with open(tcp_packets_file, 'w') as f:
        for packet in packets:
            if TCP in packet and (IP in packet or IPv6 in packet):
                packet_info = format_packet(packet)
                f.write(f"{packet_info}\n")

# Save the TCP packets
save_tcp_packets(packets, tcp_packets_file)

print("TCP packets' details have been saved.")
