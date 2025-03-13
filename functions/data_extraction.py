# This file extracts data from a .pcap file for statistical analysis.
import csv
import json
import hashlib
import requests
import humanize
import subprocess
from datetime import datetime
from collections import Counter, defaultdict

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

# Extract the TCP flows min, max, and avg duration
def tcp_min_max_avg(pcap_file):
    try:
        # Construct the tshark command to get flow statistics for TCP
        command = [
            'tshark', '-r', pcap_file, '-q', '-z', 'conv,tcp'
        ]
        
        # Run tshark command
        result = subprocess.run(command, capture_output=True, text=True)
        
        if result.returncode != 0:
            print("Error running tshark:", result.stderr)
            return
        
        # Process tshark output to remove headers, footer, and sort by bytes
        output = result.stdout
        lines = output.splitlines()

        # Skip the header lines (first 5) and the last footer line
        lines = lines[5:-1]

        # Extract the last value from each line (which is the time value)
        last_values = []
        for line in lines:
            last_value = line.split()[-1]  # Extract the last element from the split line
            last_values.append(float(last_value))  # Convert to float for calculations

        # Calculate min, max, and average
        if last_values:
            min_value = min(last_values)
            max_value = max(last_values)
            avg_value = sum(last_values) / len(last_values)
            
        return round(min_value, 4), round(max_value, 4), round(avg_value, 4)
    except:
        return "N/A", "N/A", "N/A"

# Get packet summaries from a .pcap file
def format_timestamp(timestamp):
    try:
        # Example: "Dec 24, 2024 06:28:25.354984000 Eastern Standard Time"
        dt = datetime.strptime(timestamp[:-25], "%b %d, %Y %H:%M:%S.%f")  # Remove the timezone
        formatted_time = dt.strftime("%H:%M:%S.%f")[:-3]  # Keep milliseconds (trim to 3 decimals)
        formatted_date = dt.strftime("%b %d, %Y")
        return f"{formatted_time}\n{formatted_date}"  # New format with newline
    except ValueError:
        return timestamp  # Return as-is if parsing fails

# Get packet summaries from a .pcap file
def pcap_packet_summaries(pcap_file):
    command = [
        'tshark', '-r', pcap_file, '-T', 'fields',
        '-e', 'frame.time',
        '-e', 'frame.protocols',
        '-e', 'ip.src',
        '-e', 'udp.srcport',
        '-e', 'ip.dst',
        '-e', 'udp.dstport',
        '-e', 'eth.src',
        '-e', 'eth.dst',
        '-e', 'frame.len'
    ]
    
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error running tshark:", result.stderr)
        return []

    data = []
    headers = [
        "Timestamp", "Protocols", "Source", "Source Port",
        "Destination", "Destination Port", "Source MAC", "Destination MAC", "Size"
    ]

    for line in result.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) == 9:
            packet_data = dict(zip(headers, fields))

            # Append ports to IPs
            src_ip = packet_data["Source"]
            src_port = packet_data["Source Port"]
            dst_ip = packet_data["Destination"]
            dst_port = packet_data["Destination Port"]

            packet_data["Source"] = f"{src_ip}:{src_port}" if src_port else src_ip
            packet_data["Destination"] = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
            
            # Format timestamp
            packet_data["Timestamp"] = format_timestamp(packet_data["Timestamp"])  

            data.append(packet_data)

    return data

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
    unique_ipv4_set = set()
    unique_ipv6_set = set()
    unique_flows = set()
    ipv4_counts = Counter()
    ipv6_counts = Counter()

    try:
        for packet in packet_data:
            layers = packet.get("_source", {}).get("layers", {})
            
            src_ip = layers.get("ip", {}).get("ip.src")
            dst_ip = layers.get("ip", {}).get("ip.dst")
            src_ipv6 = layers.get("ipv6", {}).get("ipv6.src")
            dst_ipv6 = layers.get("ipv6", {}).get("ipv6.dst")
            
            if src_ip:
                unique_ipv4_set.add(src_ip)
                ipv4_counts[src_ip] += 1
            if dst_ip:
                unique_ipv4_set.add(dst_ip)
                ipv4_counts[dst_ip] += 1
            
            if src_ipv6:
                unique_ipv6_set.add(src_ipv6)
                ipv6_counts[src_ipv6] += 1
            if dst_ipv6:
                unique_ipv6_set.add(dst_ipv6)
                ipv6_counts[dst_ipv6] += 1
            
            if src_ip and dst_ip:
                unique_flows.add((src_ip, dst_ip))
            if src_ipv6 and dst_ipv6:
                unique_flows.add((src_ipv6, dst_ipv6))
        
        # Getting the count and percentages of each IP protocol
        combined_ip_count = len(unique_ipv4_set) + len(unique_ipv6_set)
        ipv4percent = round((len(unique_ipv4_set) / combined_ip_count) * 100, 2) if combined_ip_count > 0 else 0
        ipv6percent = round((len(unique_ipv6_set) / combined_ip_count) * 100, 2) if combined_ip_count > 0 else 0

        # Get only the top 10 most frequent IP addresses
        combined_top_ips = dict(ipv4_counts.most_common(10))
        combined_top_ips.update(dict(ipv6_counts.most_common(10)))
        combined_top_ips = dict(sorted(combined_top_ips.items(), key=lambda x: x[1], reverse=True)[:10])

        total_count = sum(combined_top_ips.values())

        top_ips_data = {
            ip: {
                "count": count,
                "percentage": (count / total_count) * 100 if total_count > 0 else 0
            }
            for ip, count in combined_top_ips.items()
        }
        
        def probe_ip(ip):
            try:
                response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
                if response.status_code == 200:
                    return response.json()
            except requests.RequestException:
                return {}
            return {}
        
        for ip in top_ips_data:
            ip_info = probe_ip(ip)
            if ip_info.get("bogon", False):
                ip_info.update({
                    "hostname": "bogon", "city": "", "region": "",
                    "country": "bogon", "loc": "bogon", "org": "bogon",
                    "postal": "bogon", "timezone": "bogon"
                })
            
            # Combine city, region, country with a fallback if missing
            city = ip_info.get("city", "")
            region = ip_info.get("region", "")
            country = ip_info.get("country", "")
            ip_info["location"] = ", ".join(filter(None, [city, region, country]))  # Filters out empty values

            ip_info.update(top_ips_data[ip])
            top_ips_data[ip] = ip_info

        return len(unique_ipv4_set), len(unique_ipv6_set), ipv4percent, ipv6percent, combined_ip_count, len(unique_flows), {"top_ips": top_ips_data}
    
    except KeyError:
        return 0, 0, 0, 0, {}

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

# Getting the MD5 hash of the .pcap file
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

    port_counts = Counter()

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
                port_counts[src_port] += 1
            if dst_port:
                port_counts[dst_port] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

    # Keep only the top 10 most frequent ports overall
    top_ports = dict(port_counts.most_common(10))
    
    return {"top_ports": top_ports}

# Function to count L7 protocols
def application_layer_protocols(packet_data, total_packets):
    protocol_counts = defaultdict(int)

    try:
        for packet in packet_data:
            layers = packet["_source"]["layers"]

            # Extract IPv4 source and destination
            protocols = layers.get("frame", {}).get("frame.protocols", "")

            protocol_list = protocols.split(":")

            if len(protocol_list) >= 5:
                l7_protocol = protocol_list[4]
                protocol_counts[l7_protocol] += 1
    except Exception as e:
        print(f"Error processing packet: {e}")

    # Convert defaultdict to Counter to use most_common()
    top_protocols = dict(Counter(protocol_counts).most_common(10))

    # Calculate and round the percentage for each protocol
    protocol_percentages = {protocol: round((count / total_packets) * 100, 2) for protocol, count in top_protocols.items()}

    # Return both the top protocols and their percentages
    return {"top_protocols": top_protocols, "protocol_percentages": protocol_percentages}

# Function to get the top 10 MAC addresses and their percentages, including OUI resolutions
def mac_address_counts(packet_data):
    mac_counts = Counter()
    mac_details = {}

    try:
        for packet in packet_data:
            layers = packet["_source"]["layers"]
            eth_layer = layers.get("eth", {})

            src_mac = eth_layer.get("eth.src")
            dst_mac = eth_layer.get("eth.dst")

            # Fetch OUI-resolved names from eth.src_tree and eth.dst_tree
            src_oui = eth_layer.get("eth.src_tree", {}).get("eth.src.oui_resolved", "Unknown")
            dst_oui = eth_layer.get("eth.dst_tree", {}).get("eth.dst.oui_resolved", "Unknown")

            if src_mac:
                mac_counts[src_mac] += 1
                mac_details[src_mac] = src_oui  

            if dst_mac:
                mac_counts[dst_mac] += 1
                mac_details[dst_mac] = dst_oui  

    except Exception as e:
        print(f"Error processing packet: {e}")

    # Calculate total MAC count
    total_count = sum(mac_counts.values())

    # Calculate percentage for each MAC address
    mac_percentage = {
        mac: {
            "count": count,
            "percentage": (count / total_count) * 100 if total_count > 0 else 0,
            "oui_resolved": mac_details.get(mac, "Unknown")  
        }
        for mac, count in mac_counts.most_common(10)
    }

    return {"top_macs": mac_percentage}