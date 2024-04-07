# Path to the file containing the TCP packets' details
input_file = '/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/Passive_Result/40mins_tcp_packets_headers.txt'

# Path for the new file to save lines with unique source-destination pairs
output_file = '/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/Passive_Result/unique_ip_port_lines2.txt'

# Initialize a set to store unique source-destination pairs (IP and port)
unique_pairs = set()

# Initialize a list to store lines to be written to the file
unique_lines = []

# Read the input file and extract lines with unique source-destination pairs
with open(input_file, 'r') as f:
    for line in f:
        parts = line.split()
        if len(parts) > 5:
            # Extracting the full source and destination addresses (IP and port)
            src = parts[5]
            dst = parts[7]

            print(src,dst)
            pair = f"{src} > {dst}"
            # Check if the IP:port pair is unique
            if pair not in unique_pairs:
                unique_pairs.add(pair)
                unique_lines.append(line.strip())  # Add the line without trailing newline

# Write the lines with unique source-destination pairs to the output file
with open(output_file, 'w') as f:
    for line in unique_lines:
        f.write(f"{line}\n")

print(f"Lines with unique source-destination IP:port pairs have been saved to {output_file}.")
