# This file extracts data from a .pcap file for statistical analysis.
import csv
import json
import hashlib
import humanize
import subprocess
from datetime import datetime
from collections import Counter

# Convert the .pcap file to JSON using TShark
def raw_pcap_json(filepath):
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

    result = subprocess.run(
        [tshark_path, "-r", filepath, "-T", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if result.returncode != 0:
        raise Exception(f"TShark error: {result.stderr.decode('utf-8')}")

    output = result.stdout.decode("utf-8").strip()
    
    if not output:  
        raise Exception("TShark returned empty output.")

    try:
        return json.loads(output)
    except json.JSONDecodeError:
        raise Exception("Error decoding JSON from TShark output")

# Extract the start date and end date, and calculate the time difference
def packet_times_and_difference(packet_data):
    try:
        # Extract the start date from the first packet
        start_date_str = packet_data[0]["_source"]["layers"]["frame"]["frame.time"]
        start_date_part = " ".join(start_date_str.split()[:-3])  # Remove the timezone
        start_date_part = start_date_part[:start_date_part.find(".") + 7]  # Fix microseconds length
        start_dt = datetime.strptime(start_date_part, "%b %d, %Y %H:%M:%S.%f")
        
        # Extract the end date from the last packet
        end_date_str = packet_data[-1]["_source"]["layers"]["frame"]["frame.time"]
        end_date_part = " ".join(end_date_str.split()[:-3])  # Remove the timezone
        end_date_part = end_date_part[:end_date_part.find(".") + 7]  # Fix microseconds length
        end_dt = datetime.strptime(end_date_part, "%b %d, %Y %H:%M:%S.%f")

        # Calculate the time difference
        time_diff = end_dt - start_dt
        
        # Humanize the time difference
        time_diff_humanized = humanize.naturaldelta(time_diff)
        
        # Format dates for display
        start_date_formatted = start_dt.strftime("%m/%d/%Y at %I:%M:%S %p").lstrip("0").replace("/0", "/")
        end_date_formatted = end_dt.strftime("%m/%d/%Y at %I:%M:%S %p").lstrip("0").replace("/0", "/")
        
        return start_date_formatted, end_date_formatted, time_diff_humanized
    
    except KeyError:
        return "-", "-", "Error processing dates"

# Count occurrences of "_index" in each dictionary inside the packet_data list
def total_packets(packet_data):
    try:
        total = sum(1 for packet in packet_data if "_index" in packet)
        return total
    except Exception as e:
        return "-"

# Count of unique IPv4 and IPv6 addresses and flows, with combined IP count
def unique_ips_and_flows(packet_data):
    unique_ipv4_set = set()  # Stores all unique IPv4 IPs
    unique_ipv6_set = set()  # Stores all unique IPv6 IPs
    unique_flows = set()     # Stores all unique (src, dst) pairs

    try:
        for packet in packet_data:
            layers = packet["_source"]["layers"]

            # Extract IPv4 source and destination
            src_ip = layers.get("ip", {}).get("ip.src")
            dst_ip = layers.get("ip", {}).get("ip.dst")

            # Extract IPv6 source and destination
            src_ipv6 = layers.get("ipv6", {}).get("ipv6.src")
            dst_ipv6 = layers.get("ipv6", {}).get("ipv6.dst")

            # Add unique IPv4 IPs to the set
            if src_ip:
                unique_ipv4_set.add(src_ip)
            if dst_ip:
                unique_ipv4_set.add(dst_ip)

            # Add unique IPv6 IPs to the set
            if src_ipv6:
                unique_ipv6_set.add(src_ipv6)
            if dst_ipv6:
                unique_ipv6_set.add(dst_ipv6)

            # Add unique IP-to-IP flows to the set (separating IPv4 and IPv6 flows)
            if src_ip and dst_ip:
                unique_flows.add((src_ip, dst_ip))
            if src_ipv6 and dst_ipv6:
                unique_flows.add((src_ipv6, dst_ipv6))

        # Calculate the combined IP count
        combined_ip_count = len(unique_ipv4_set) + len(unique_ipv6_set)

        return len(unique_ipv4_set), len(unique_ipv6_set), combined_ip_count, len(unique_flows)

    except KeyError:
        return 0, 0, 0, 0
    
# Load protocol numbers into a dictionary
def load_protocol_mapping(csv_file):
    protocol_mapping = {}
    try:
        with open(csv_file, mode="r", encoding="utf-8") as file:
            reader = csv.DictReader(file)
            for row in reader:
                protocol_mapping[row["number"]] = row["protocol"]
    except Exception as e:
        print(f"Error loading protocol mapping: {e}")
    return protocol_mapping

# Function to analyze protocol distribution
def protocol_distribution(packet_data, csv_file="information-sheets/protocol-numbers.csv"):
    protocol_counts = {}
    protocol_mapping = load_protocol_mapping(csv_file)

    try:
        for packet in packet_data:
            layers = packet["_source"]["layers"]

            # Check if IP layer exists and get protocol number
            ip_layer = layers.get("ip", {})
            if ip_layer:
                ip_proto = ip_layer.get("ip.proto")

                if ip_proto:
                    # Get protocol name from CSV mapping, default to "Unknown"
                    protocol = protocol_mapping.get(ip_proto, "Unknown")

                    # Increment the count for this protocol
                    protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

            # Additional checks for TCP and UDP layers
            if "udp" in layers:
                protocol_counts["UDP"] = protocol_counts.get("UDP", 0) + 1
            if "tcp" in layers:
                protocol_counts["TCP"] = protocol_counts.get("TCP", 0) + 1

    except Exception as e:
        print(f"Error processing packet: {e}")

    return protocol_counts

# Getting the MD5 hash of the .pcap file.
def md5_hash(file_storage):
    hasher = hashlib.md5()
    try:
        while chunk := file_storage.read(4096):
            hasher.update(chunk)
        file_storage.seek(0)
        return hasher.hexdigest()
    except Exception as e:
        return f"Error processing file: {str(e)}"

# Function to fetch L4 port numbers
def transport_layer_ports(packet_data):
    src_ports = Counter()
    dst_ports = Counter()

    try:
        for packet in packet_data:
            layers = packet["_source"]["layers"]

            # Check for TCP layer
            if "tcp" in layers:
                src_port = layers["tcp"].get("tcp.srcport")
                dst_port = layers["tcp"].get("tcp.dstport")
            # Check for UDP layer
            elif "udp" in layers:
                src_port = layers["udp"].get("udp.srcport")
                dst_port = layers["udp"].get("udp.dstport")
            else:
                continue  # Skip packets that don't have TCP or UDP

            # Increment the count for each port
            if src_port:
                src_ports[src_port] += 1
            if dst_port:
                dst_ports[dst_port] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

    # Keep only the top 10 most frequent ports in each category
    top_src_ports = dict(src_ports.most_common(10))
    top_dst_ports = dict(dst_ports.most_common(10))

    return {"top_source_ports": top_src_ports, "top_destination_ports": top_dst_ports}