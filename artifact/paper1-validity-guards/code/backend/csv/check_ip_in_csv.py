import ipaddress
import csv

# Path to your CSV file
csv_file_path = "country_asn.csv"

def ip_in_range(ip, start_ip, end_ip):
    """Check if an IP address is within the range."""
    try:
        # Convert IPs to objects for comparison
        ip = ipaddress.ip_address(ip)
        start_ip = ipaddress.ip_address(start_ip)
        end_ip = ipaddress.ip_address(end_ip)

        # Ensure IPs are of the same version (IPv4/IPv6)
        if ip.version == start_ip.version == end_ip.version:
            return start_ip <= ip <= end_ip
        else:
            return False
    except ValueError as e:
        print(f"Error processing IP range: {e}")
        return False

def check_ip_in_csv(ip_to_check, csv_path):
    """Check if an IP address exists within any range in the CSV."""
    with open(csv_path, mode="r", encoding="utf-8") as csv_file:
        csv_reader = csv.DictReader(csv_file)
        for row in csv_reader:
            try:
                start_ip = row.get("start_ip")
                end_ip = row.get("end_ip")
                if start_ip and end_ip and ip_in_range(ip_to_check, start_ip, end_ip):
                    return row  # Return the matching row
            except ValueError as e:
                print(f"Error parsing IP range: {e}")
    return None

# IP to check
ip_to_check = "103.102.230.5"

# Run the check
result = check_ip_in_csv(ip_to_check, csv_file_path)

if result:
    print(f"IP {ip_to_check} found in range: {result}")
else:
    print(f"IP {ip_to_check} not found in any range.")
