import socket
import csv

file_path = '/Users/ertugrulgazitekden/Desktop/NALs/ECN_Transversial/.tranco/7PPX-DEFAULT.csv'

# Resolve each domain to its IP and save
with open(file_path, 'r') as csv_file, open('Tranco_list', 'w') as output_file:
    csv_reader = csv.reader(csv_file)
    next(csv_reader)  # Skip the header row
    count = 0
    for row in csv_reader:
        domain = row[1]  # Assuming the second column contains the domain names
        try:
            ip = socket.gethostbyname(domain)
            print(f"{domain} -> {ip}")
            output_file.write(f"{ip}\n")
        except socket.gaierror:
            print(f"Could not get IP for {domain}")
        count += 1
        if count >= 100000:  # Stop after resolving 10,000 domains
            break

print("IP addresses saved to ips.txt")
