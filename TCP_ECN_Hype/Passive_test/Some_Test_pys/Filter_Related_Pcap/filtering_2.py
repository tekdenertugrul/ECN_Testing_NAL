# Path to the file with unique source-destination pairs
input_file = '/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/Passive_Result/unique_ip_port_lines2.txt'

# Path for the new file to save lines with specific ECN, ECE, and CWR details
output_file = '/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/Passive_Result/specific_ecn_tcp_info2.txt'

# Initialize a list to store lines to be written to the file
specific_lines = []

# Read the input file and extract lines with specific ECN, ECE, and CWR details
with open(input_file, 'r') as f:
    for line in f:
        parts = line.split(', ')
        ip_ecn = parts[1].split(': ')[1]  # Extracting IP ECN
        tcp_ece = parts[2].split(': ')[1]  # Extracting TCP ECE
        tcp_cwr = parts[3].split(': ')[1].strip()  # Extracting TCP CWR

        # Convert string representations to boolean/int where necessary
        tcp_ece_bool = tcp_ece == 'True'
        tcp_cwr_bool = tcp_cwr == 'True'
        ip_ecn_int = int(ip_ecn)

        # Check if the conditions are met
        if ip_ecn_int != 0 or tcp_ece_bool or tcp_cwr_bool:
            specific_lines.append(line.strip())

# Write the lines that meet the criteria to the output file
with open(output_file, 'w') as f:
    for line in specific_lines:
        f.write(f"{line}\n")

print(f"Lines with specific ECN, ECE, and CWR conditions have been saved to {output_file}.")
