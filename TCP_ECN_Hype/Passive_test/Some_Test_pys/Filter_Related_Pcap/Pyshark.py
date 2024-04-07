import pyshark

# Path to your pcapng file
file_path = '/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/Passive_test/Pcapy/Tshark_Process_Hype/ITU_Passive_Testes.pcapng'
target_ip = '194.1.147.65'
output_file = 'analysis_output.txt'  # Define the output file path

# Read the pcapng file
cap = pyshark.FileCapture(file_path, display_filter=f"ip.addr == {target_ip}")

with open(output_file, 'w') as f:
    for packet in cap:
        try:
            # Common IP Details
            src_ip = packet.ip.src
            dst_ip = packet.ip.dst
            ds_field = packet.ip.dsfield  # ECN information within the DS field
            ecn = format(int(ds_field, 16), '02b')[-2:]
            ecn_meaning = {
                '00': 'Non-ECN-Capable Transport, Non-ECT',
                '10': 'ECN Capable Transport, ECT(0)',
                '01': 'ECN Capable Transport, ECT(1)',
                '11': 'Congestion Encountered, CE',
            }

            # Check if the packet is TCP
            if 'TCP' in packet:
                src_port = packet.tcp.srcport
                dst_port = packet.tcp.dstport
                seq_num = packet.tcp.seq
                ack_num = packet.tcp.ack
                tcp_flags = packet.tcp.flags
                f.write(f"TCP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, Seq: {seq_num}, Ack: {ack_num}, Flags: {tcp_flags}, ECN: {ecn_meaning[ecn]} ({ecn})\n")

            # Check if the packet is UDP
            elif 'UDP' in packet:
                src_port = packet.udp.srcport
                dst_port = packet.udp.dstport
                f.write(f"UDP Packet: {src_ip}:{src_port} -> {dst_ip}:{dst_port}, ECN: {ecn_meaning[ecn]} ({ecn})\n")

            # Check if the packet is ICMP
            elif 'ICMP' in packet:
                icmp_type = packet.icmp.type
                icmp_code = packet.icmp.code
                f.write(f"ICMP Packet: {src_ip} -> {dst_ip}, Type: {icmp_type}, Code: {icmp_code}, ECN: {ecn_meaning[ecn]} ({ecn})\n")

        except AttributeError:
            # Handle the case where a packet doesn't have expected layers or fields
            continue
