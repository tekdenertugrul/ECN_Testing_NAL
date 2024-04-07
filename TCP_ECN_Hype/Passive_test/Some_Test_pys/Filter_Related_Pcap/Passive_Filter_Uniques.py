import pyshark

file_path = '/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/Passive_test/Pcapy/Tshark_Process_Hype/Turkey_Tested_My_Home.pcapng'
output_file = 'Filtering_.txt'

cap = pyshark.FileCapture(file_path)

conversations = set()

with open(output_file, 'w') as f:
    for packet in cap:
        try:
            # Common IP Details
            if 'IP' in packet:
                src_ip = packet.ip.src
                dst_ip = packet.ip.dst
                ds_field = packet.ip.dsfield
                ecn = format(int(ds_field, 16), '02b')[-2:]  # Extracting ECN bits

                # TCP Packets
                if 'TCP' in packet:
                    conversation_id = ('TCP', src_ip, packet.tcp.srcport, dst_ip, packet.tcp.dstport)

                    if conversation_id not in conversations:
                        conversations.add(conversation_id)
                        f.write(f"TCP Conversation: {src_ip}:{packet.tcp.srcport} -> {dst_ip}:{packet.tcp.dstport}\n")
                        f.write(f"TCP Details - Flags: {packet.tcp.flags}, Seq: {packet.tcp.seq}, Ack: {packet.tcp.ack}\n")
                        f.write(f"IP ECN: {ecn}\n\n")

                # UDP Packets
                elif 'UDP' in packet:
                    conversation_id = ('UDP', src_ip, packet.udp.srcport, dst_ip, packet.udp.dstport)

                    if conversation_id not in conversations:
                        conversations.add(conversation_id)
                        f.write(f"UDP Conversation: {src_ip}:{packet.udp.srcport} -> {dst_ip}:{packet.udp.dstport}\n")
                        f.write(f"IP ECN: {ecn}\n\n")

                # ICMP Packets
                elif 'ICMP' in packet:
                    conversation_id = ('ICMP', src_ip, dst_ip, packet.icmp.type, packet.icmp.code)

                    if conversation_id not in conversations:
                        conversations.add(conversation_id)
                        f.write(f"ICMP Interaction: {src_ip} -> {dst_ip}, Type: {packet.icmp.type}, Code: {packet.icmp.code}\n")
                        f.write(f"IP ECN: {ecn}\n\n")

        except AttributeError:
            # Handle the case where a packet doesn't have expected layers or fields
            continue
