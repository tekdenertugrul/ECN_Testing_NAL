from scapy.all import *

def check_reachability(target_ip, output_file="reachable_ips_from_turkey.txt"):
    # Constructing the IP layer
    ip = IP(dst=target_ip)
    
    # Constructing the ICMP layer
    icmp = ICMP()
    
    # Sending the packet
    pkt = ip/icmp
    resp = sr1(pkt, timeout=1, verbose=0)  # Increase timeout to 1 seconds

    
    if resp is None:
        print(f"No response from {target_ip}")
    elif resp.haslayer(ICMP):
        if int(resp[ICMP].type) == 0 and int(resp[ICMP].code) == 0:
            print(f"{target_ip} is reachable")
            with open(output_file, "a") as file:
                file.write(target_ip + "\n")
        else:
            print(f"{target_ip} is unreachable")
    else:
        print(f"Unexpected response from {target_ip}")

# Read the file and check each IP for reachability
with open('/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/First_Try_With_1K/ips1000k.txt', 'r') as file:
    for line in file:
        target_ip = line.strip()  # Remove newline characters and any leading/trailing whitespace
        check_reachability(target_ip)
