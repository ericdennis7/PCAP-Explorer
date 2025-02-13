# This file extracts data from a .pcap file for statistical analysis.
import json
import hashlib
import humanize
import subprocess
from datetime import datetime

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

# Count of unique IP addresses
def unique_ips_and_flows(packet_data):
    unique_ip_set = set()  # Stores all unique IPs
    unique_flows = set()   # Stores all unique (src, dst) pairs

    try:
        for packet in packet_data:
            layers = packet["_source"]["layers"]

            # Extract IPv4 source and destination
            src_ip = layers.get("ip", {}).get("ip.src")
            dst_ip = layers.get("ip", {}).get("ip.dst")

            # Extract IPv6 source and destination
            src_ipv6 = layers.get("ipv6", {}).get("ipv6.src")
            dst_ipv6 = layers.get("ipv6", {}).get("ipv6.dst")

            # Add unique IPs to the set
            if src_ip:
                unique_ip_set.add(src_ip)
            if dst_ip:
                unique_ip_set.add(dst_ip)
            if src_ipv6:
                unique_ip_set.add(src_ipv6)
            if dst_ipv6:
                unique_ip_set.add(dst_ipv6)

            # Add unique IP-to-IP flows to the set
            if src_ip and dst_ip:
                unique_flows.add((src_ip, dst_ip))
            if src_ipv6 and dst_ipv6:
                unique_flows.add((src_ipv6, dst_ipv6))

        return len(unique_ip_set), len(unique_flows)

    except KeyError:
        return 0, 0

# Getting the MD5 hash of the .pcap file.
def md5_hash(file_storage):
    """Compute MD5 hash of an uploaded file (Flask FileStorage object)."""
    hasher = hashlib.md5()
    try:
        while chunk := file_storage.read(4096):  # Read directly from FileStorage
            hasher.update(chunk)
        file_storage.seek(0)  # Reset file pointer after reading
        return hasher.hexdigest()
    except Exception as e:
        return f"Error processing file: {str(e)}"
