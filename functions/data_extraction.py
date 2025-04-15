# Eric Dennis
# Started: 3/25/2025
# Description: This file contains all the data extraction functions for the PCAP Visualizer application.

# Last Updated: 3/25/2025
# Update Notes: Added the get_top_conversations function to extract the top conversations from a .pcap file.

# Imports
import re
import os
import csv
import json
import time
import logging
import random
import hashlib
import requests
import ipaddress
import subprocess
import pandas as pd
from io import StringIO
from datetime import datetime
from dotenv import load_dotenv
from collections import Counter, defaultdict

# Getting environment variables
load_dotenv()

# Convert the .pcap file to DataFrame using TShark
def raw_pcap_pd(filepath):
    fields = [
        "frame.number",
        "frame.time",
        "frame.time_epoch",
        "frame.len",
        "frame.protocols",
        "eth.src",
        "eth.dst",
        "eth.src.oui_resolved",
        "eth.dst.oui_resolved",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
        "ip.proto",
        "tcp.srcport",
        "tcp.dstport",
        "udp.srcport",
        "udp.dstport"
    ]

    cmd = [
        "/usr/bin/tshark", "-r", filepath, "-T", "fields",
        *sum([["-e", field] for field in fields], []),
        "-E", "separator=,", "-E", "quote=d", "-E", "header=y"
    ]

    result = subprocess.run(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    if result.returncode != 0:
        raise Exception(f"TShark error: {result.stderr.decode('utf-8')}")

    output = result.stdout.decode("utf-8").strip()

    if not output:
        raise Exception("TShark returned empty output.")

    # Convert CSV string to DataFrame
    data = StringIO(output)
    df = pd.read_csv(data)
    
    # Convert relevant fields to integers where possible
    fields_to_convert = [
        "ip.proto",
        "tcp.srcport", "tcp.dstport",
        "udp.srcport", "udp.dstport"
    ]

    for field in fields_to_convert:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors="coerce") .astype("Int64")

    return df

# Extract the TCP flows min, max, and avg duration
def tcp_min_max_avg(pcap_file):
    try:
        # Construct the tshark command to get flow statistics for TCP
        command = [
            '/usr/bin/tshark', '-r', pcap_file, '-q', '-z', 'conv,tcp'
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
            last_value = line.split()[-1]
            last_values.append(float(last_value))

        # Calculate min, max, and average
        if last_values:
            min_value = min(last_values)
            max_value = max(last_values)
            avg_value = sum(last_values) / len(last_values)
            
        return round(min_value, 4), round(max_value, 4), round(avg_value, 4)
    except:
        return "N/A", "N/A", "N/A"
    
# Extract the UDP flows min, max, and avg duration
def udp_min_max_avg(pcap_file):
    try:
        # Construct the tshark command to get flow statistics for UDP
        command = [
            '/usr/bin/tshark', '-r', pcap_file, '-q', '-z', 'conv,udp'
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
            last_value = line.split()[-1] 
            last_values.append(float(last_value)) 

        # Calculate min, max, and average
        if last_values:
            min_value = min(last_values)
            max_value = max(last_values)
            avg_value = sum(last_values) / len(last_values)
            
        return round(min_value, 4), round(max_value, 4), round(avg_value, 4)
    except:
        return "N/A", "N/A", "N/A"

# Extract the start date and end date, and calculate the time difference
def packet_times_and_difference(packet_data):
    try:
        # Extract start date (first row)
        start_date_str = packet_data.iloc[0]["frame.time"]
        try:
            # Remove the timezone and extra spaces
            start_date_part = " ".join(start_date_str.rsplit(" ", 3)[:-1])  
            start_date_part = " ".join(start_date_part.split()) 
            start_date_part = start_date_part[:start_date_part.find(".") + 7] 
            start_dt = datetime.strptime(start_date_part, "%b %d, %Y %H:%M:%S.%f")
            start_date_formatted = start_dt.strftime("%m/%d/%Y at %I:%M:%S %p").lstrip("0").replace("/0", "/")
        except Exception:
            start_date_formatted = start_date_str
        
        # Extract end date (last row)
        end_date_str = packet_data.iloc[-1]["frame.time"]
        try:
            end_date_part = " ".join(end_date_str.rsplit(" ", 3)[:-1])
            end_date_part = " ".join(end_date_part.split())  
            end_date_part = end_date_part[:end_date_part.find(".") + 7] 
            end_dt = datetime.strptime(end_date_part, "%b %d, %Y %H:%M:%S.%f")
            end_date_formatted = end_dt.strftime("%m/%d/%Y at %I:%M:%S %p").lstrip("0").replace("/0", "/")
        except Exception:
            end_date_formatted = end_date_str

        # Calculate the time difference
        try:
            time_diff = end_dt - start_dt
            total_seconds = int(time_diff.total_seconds())

            hours, remainder = divmod(total_seconds, 3600)
            minutes, seconds = divmod(remainder, 60)

            if hours > 0:
                time_diff_humanized = f"{hours}h {minutes}m {seconds}s"
            elif minutes > 0:
                time_diff_humanized = f"{minutes}m {seconds}s"
            else:
                time_diff_humanized = f"{seconds}s"

        except Exception:
            time_diff_humanized = "Error calculating time difference"

        return start_date_formatted, end_date_formatted, time_diff_humanized
    
    except (KeyError, IndexError) as e:
        return "-", "-", f"Error processing dates: {str(e)}"

# Count occurrences of "_index" in each dictionary inside the packet_data list
def total_packets(df):
    try:
        # Count the number of rows in the DataFrame
        total = len(df)
        return total
    except Exception as e:
        print(f"Error: {e}")
        return "-"
    
def sanitize_for_json(data):
    if isinstance(data, dict):
        return {k: sanitize_for_json(v) for k, v in data.items() if v is not None}
    elif isinstance(data, list):
        return [sanitize_for_json(item) for item in data if item is not None]
    elif data is None:
        return ""
    elif isinstance(data, (str, int, float, bool)):
        return data
    else:
        # Convert any other type to string
        return str(data)

# Function to get the unique IP addresses and their counts
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def unique_ips_and_flows(pcap_file):

    ip_info_token = os.getenv('IP_INFO')
    if not ip_info_token:
        logger.error("IP_INFO environment variable is not set")
        return 0, 0, 0, 0, 0, {"error": "IP_INFO token not configured"}

    full_path = os.path.join("/home/ubuntu/PCAP-Visualizer", pcap_file)
    logger.info(f"Processing PCAP file: {full_path}")

    tshark_cmd = ["/usr/bin/tshark", "-r", full_path, "-T", "fields", "-e", "ip.src", "-e", "ip.dst"]

    try:
        logger.info("Running tshark command to extract IPs")
        result = subprocess.run(tshark_cmd, capture_output=True, text=True, check=True)
        output = result.stdout.strip().splitlines()

        ip_list = []
        for line in output:
            ips = line.split('\t')
            ip_list.extend(ip for ip in ips if ip)

        ip_counts = Counter(ip_list)

        ipv4_counts = Counter({ip: count for ip, count in ip_counts.items() if ':' not in ip})
        ipv6_counts = Counter({ip: count for ip, count in ip_counts.items() if ':' in ip})

        total_ipv4_count = sum(ipv4_counts.values())
        total_ipv6_count = sum(ipv6_counts.values())
        combined_ip_count = total_ipv4_count + total_ipv6_count

        ipv4_percent = round((total_ipv4_count / combined_ip_count) * 100, 2) if combined_ip_count > 0 else 0
        ipv6_percent = round((total_ipv6_count / combined_ip_count) * 100, 2) if combined_ip_count > 0 else 0

        top_ipv4_ips = dict(ipv4_counts.most_common(100))
        top_ipv6_ips = dict(ipv6_counts.most_common(100))
        combined_top_ips = dict(sorted({**top_ipv4_ips, **top_ipv6_ips}.items(), key=lambda x: x[1], reverse=True)[:100])
        total_count = sum(combined_top_ips.values())

        def probe_ip(ip):
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0'
                }
                url = f"https://ipinfo.io/{ip}/json/?token={ip_info_token}"
                logger.info(f"Requesting info for IP: {ip}")
                response = requests.get(url, headers=headers, timeout=10)
                logger.info(f"Response status for {ip}: {response.status_code}")

                if response.status_code == 200:
                    return response.json()
                else:
                    logger.error(f"Error response for {ip}: {response.status_code}, {response.text}")
                    return {
                        "error": f"Status code: {response.status_code}",
                        "hostname": "unknown", "city": "", "region": "",
                        "country": "unknown", "loc": "", "org": "",
                        "postal": "", "timezone": ""
                    }

            except requests.exceptions.Timeout:
                logger.error(f"Timeout fetching data for {ip}")
                return {"error": "Request timed out", "hostname": "timeout", "city": "", "region": "", "country": "", "loc": "", "org": "", "postal": "", "timezone": ""}
            except requests.exceptions.RequestException as e:
                logger.error(f"Request error fetching data for {ip}: {str(e)}")
                return {"error": str(e), "hostname": "error", "city": "", "region": "", "country": "", "loc": "", "org": "", "postal": "", "timezone": ""}
            except Exception as e:
                logger.error(f"Unexpected error for {ip}: {str(e)}")
                return {"error": f"Unexpected error: {str(e)}", "hostname": "error", "city": "", "region": "", "country": "", "loc": "", "org": "", "postal": "", "timezone": ""}

        logger.info(f"Fetching geolocation data for {len(combined_top_ips)} IPs")
        top_ips_data = {}
        for rank, (ip, count) in enumerate(combined_top_ips.items(), start=1):
            logger.info(f"Processing IP {rank}/{len(combined_top_ips)}: {ip}")
            ip_info = probe_ip(ip)

            if ip_info.get("bogon", False):
                ip_info.update({
                    "hostname": "bogon", "city": "", "region": "",
                    "country": "bogon", "loc": "bogon", "org": "bogon",
                    "postal": "", "timezone": ""
                })

            city = ip_info.get("city", "")
            region = ip_info.get("region", "")
            country = ip_info.get("country", "")
            ip_info["location"] = ", ".join(filter(None, [city, region, country]))

            ip_info.update({
                "count": count,
                "percentage": round((count / total_count) * 100, 2) if total_count > 0 else 0,
                "rank": rank
            })

            top_ips_data[ip] = ip_info

        logger.info("Completed processing all IPs")
        return total_ipv4_count, total_ipv6_count, ipv4_percent, ipv6_percent, combined_ip_count, {"top_ips": sanitize_for_json(top_ips_data)}

    except subprocess.CalledProcessError as e:
        logger.error(f"Error running tshark: {e}")
        logger.error(f"Return code: {e.returncode}")
        logger.error(f"Command: {e.cmd}")
        logger.error(f"stdout: {e.stdout}")
        logger.error(f"stderr: {e.stderr}")
        return 0, 0, 0, 0, 0, {"error": f"Error running tshark: {str(e)}"}
    except Exception as e:
        logger.error(f"Unexpected error in unique_ips_and_flows: {str(e)}")
        return 0, 0, 0, 0, 0, {"error": f"Unexpected error: {str(e)}"}
    
# Load protocol numbers into a dictionary
def load_protocol_mapping(csv_file):
    protocol_mapping = {}
    try:
        with open(csv_file, mode="r", encoding="utf-8-sig") as file:
            reader = csv.DictReader(file)

            for row in reader:
                if row.get("number") and row.get("protocol"):
                    # Strip whitespace and ensure consistent keys
                    protocol_mapping[row["number"].strip()] = row["protocol"].strip()

    except Exception as e:
        print(f"Error loading protocol mapping: {e}")
    return protocol_mapping

# Function to analyze protocol distribution
def protocol_distribution(df, total_packets, csv_file="/home/ubuntuPCAP-Visualizer/information-sheets/protocol-numbers.csv"):
    protocol_counts = {}
    protocol_mapping = load_protocol_mapping(csv_file)

    try:
        for _, row in df.iterrows():
            ip_proto = row.get("ip.proto")

            # Convert to string for consistent lookup
            if ip_proto is not None:
                protocol = protocol_mapping.get(str(ip_proto), "Unknown")
                protocol_counts[protocol] = protocol_counts.get(protocol, 0) + 1

            # Avoid double counting for TCP and UDP
            if "udp" in row and "ip.src" not in row:
                protocol_counts["UDP"] = protocol_counts.get("UDP", 0) + 1
            if "tcp" in row and "ip.src" not in row:
                protocol_counts["TCP"] = protocol_counts.get("TCP", 0) + 1

    except Exception as e:
        print(f"Error processing packet: {e}")

    # Keep only the top 7 most frequent protocols
    top_protocols = dict(Counter(protocol_counts).most_common(7))

    # Calculate percentage for each protocol, but cap it at the top 7 protocols
    protocol_percentages = {protocol: round((count / total_packets) * 100, 2) for protocol, count in top_protocols.items()}

    return {"top_protocols": top_protocols, "protocol_percentages": protocol_percentages}

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
def transport_layer_ports(df, total_packets):
    port_counts = Counter()

    try:
        for _, row in df.iterrows():
            # Fetch ports directly using .get() to avoid key errors
            src_port = pd.to_numeric(row.get("tcp.srcport"), errors="coerce")
            dst_port = pd.to_numeric(row.get("tcp.dstport"), errors="coerce")

            if pd.notna(src_port):
                port_counts[src_port] += 1
            if pd.notna(dst_port):
                port_counts[dst_port] += 1

            src_port = pd.to_numeric(row.get("udp.srcport"), errors="coerce")
            dst_port = pd.to_numeric(row.get("udp.dstport"), errors="coerce")

            if pd.notna(src_port):
                port_counts[src_port] += 1
            if pd.notna(dst_port):
                port_counts[dst_port] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")
        
    # Calculate percentage based on total packets
    top_7_ports = dict(port_counts.most_common(7))
    port_percentages = {
        port: round((count / (total_packets * 2)) * 100, 2)  
        for port, count in top_7_ports.items() 
    }

    # Keep only the top 10 most frequent ports for display
    top_ports = dict(port_counts.most_common(7)) 

    return {"top_ports": top_ports, "port_percentages": port_percentages}

# Function to get the top L7 application layer protocols.
def application_layer_protocols(df):
    protocol_counts = defaultdict(int)
    total_l7_packets = 0

    try:
        for _, row in df.iterrows():
            protocols = row.get("frame.protocols", "")
            protocol_list = protocols.split(":")

            if len(protocol_list) >= 5:
                l7_protocol = protocol_list[4]
                protocol_counts[l7_protocol] += 1
                total_l7_packets += 1
    except Exception as e:
        print(f"Error processing packet: {e}")

    # Calculate the percentage based on L7 packets only
    protocol_percentages = {
        protocol: round((count / total_l7_packets) * 100, 2) 
        for protocol, count in protocol_counts.items()
    }

    # Keep only the top 7 most frequent protocols for display
    top_protocols = dict(Counter(protocol_counts).most_common(7))

    return {"top_protocols": top_protocols, "protocol_percentages": protocol_percentages}

# Function to get the top 100 MAC addresses and their percentages, including OUI resolutions
def mac_address_counts(df):
    mac_counts = Counter()
    mac_details = {}

    try:
        for _, row in df.iterrows():
            src_mac = row.get("eth.src")
            dst_mac = row.get("eth.dst")

            src_oui = row.get("eth.src.oui_resolved", "Unknown")
            dst_oui = row.get("eth.dst.oui_resolved", "Unknown")

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
        for mac, count in mac_counts.most_common(50)
    }

    return {"top_macs": mac_percentage}

# Group packets by time section
def group_packets_by_time_section(df, num_sections=20):
    # Convert frame.time_epoch to numeric if not already
    df['frame.time_epoch'] = pd.to_numeric(df['frame.time_epoch'], errors='coerce')

    # Find the min and max of frame.time_epoch
    min_time = df['frame.time_epoch'].min()
    max_time = df['frame.time_epoch'].max()

    # Calculate the interval size based on the number of sections
    interval_size = (max_time - min_time) / num_sections

    # Create the time sections (intervals) in epoch format
    time_sections = [(min_time + i * interval_size, min_time + (i + 1) * interval_size) for i in range(num_sections)]

    # Group packets by time section and calculate the packet count and total bytes for each section
    section_counts = {
        f"Section {i+1} ({start})": {  # Keep the epoch time in the key
            "packet_count": len(df[(df['frame.time_epoch'] >= start) & (df['frame.time_epoch'] < end)]),
            "total_bytes": int(df[(df['frame.time_epoch'] >= start) & (df['frame.time_epoch'] < end)]['frame.len'].sum())  # Convert np.int64 to int
        }
        for i, (start, end) in enumerate(time_sections)
    }

    return section_counts

# Function to run Snort on a .pcap file and parse the output
def snort_rules(pcap_file):
    # Run the Snort command and capture its output
    command = [
        "/usr/sbin/snort", "-q", "-r", pcap_file, "-c", "/etc/snort/snort.conf", "-A", "console"
    ]

    # Run Snort command and capture stdout
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Get the Snort output from stdout
    snort_output = result.stdout

    # Regular expression pattern to capture each part
    pattern = re.compile(r'(?P<Date>\d{2}/\d{2})-(?P<Time>\d{2}:\d{2}:\d{2}\.\d+)  \[\*\*] \[(?P<RuleID>\d+:\d+:\d+)\] (?P<Message>.*?) \[\*\*] \[Classification: (?P<Classification>.*?)\] \[Priority: (?P<Priority>\d+)\] \{(?P<Protocol>\w+)\} (?P<Source>[\d\.\:]+) -> (?P<Dest>[\d\.\:]+)')

    # Lists to store extracted data
    data = []
    source_ips = []
    dest_ips = []
    rule_ids = []
    priorities = []

    # Parse each log entry in the Snort output
    for log in snort_output.splitlines():
        match = pattern.match(log)
        if match:
            log_data = match.groupdict()
            data.append(log_data)

            # Collect data for top source IP, destination IP, rule ID, and priorities
            source_ips.append(log_data['Source'])
            dest_ips.append(log_data['Dest'])
            rule_ids.append(log_data['RuleID'])
            priorities.append(int(log_data['Priority']))

    # Get the top source IP, destination IP, rule ID, and count of each priority level
    top_source_ip = Counter(source_ips).most_common(1)
    top_dest_ip = Counter(dest_ips).most_common(1)
    top_rule_id = Counter(rule_ids).most_common(1)
    priority_counts = Counter(priorities)

    # Prepare the results
    result_data = {
        "top_source_ip": top_source_ip[0][0] if top_source_ip else "N/A",
        "top_dest_ip": top_dest_ip[0][0] if top_dest_ip else "N/A",
        "top_rule_id": top_rule_id[0][0] if top_rule_id else "N/A",
        "priority_1_count": priority_counts.get(1, 0),
        "priority_2_count": priority_counts.get(2, 0),
        "priority_3_count": priority_counts.get(3, 0),
    }

    # Convert the list of data to JSON
    json_output = json.dumps({"data": data, "summary": result_data}, indent=4)

    # Return both json_output and summary values
    return json_output, result_data["top_source_ip"], result_data["top_dest_ip"], result_data["top_rule_id"], result_data["priority_1_count"], result_data["priority_2_count"], result_data["priority_3_count"]

# Get location information for an IP address
def get_ip_location(ip_address):
    """Fetch the location of the IP address using the ipinfo.io API."""
    try:
        # Request location data from ipinfo.io API
        response = requests.get(f"https://ipinfo.io/{ip_address}/json/?token={os.getenv('IP_INFO')}", timeout=3)
        data = response.json()

        # Return relevant information (including country)
        return {
            "location": data.get("loc", None),
            "country": data.get("country", None),
        }
    except requests.exceptions.RequestException as e:
        print(f"Error fetching location for {ip_address}: {e}")
        return None

# Function to check if the IP falls under any of the categories to exclude
def is_excluded_ip(ip_address):
    try:
        ip_object = ipaddress.ip_address(ip_address)
        return ip_object.is_global
    except ValueError:
        return False

# Function to parse conversations from tshark output
def parse_conversations(protocol, tshark_output):
    conversations = []

    for line in tshark_output[1:]:  # Skip header line
        fields = line.split()
        if len(fields) >= 10:  # Ensure there are enough fields (packet count in 10th column)
            try:
                src_ip = fields[0].split(":")[0]
                dst_ip = fields[2].split(":")[0]
                packet_count = int(fields[9])  # Packet count

                # Skip excluded (non-public) IPs
                if is_excluded_ip(src_ip) == False or is_excluded_ip(dst_ip) == False:
                    continue

                conversations.append({
                    "IP A": src_ip,
                    "IP B": dst_ip,
                    "Packets": packet_count,
                    "Protocol": protocol
                })
            except ValueError:
                continue

    return conversations

# Function to get the top conversations from a .pcap file (TCP and UDP)
def get_top_conversations(pcap_file, limit=50):
    # Run tshark to extract TCP and UDP conversations
    tcp_command = ["/usr/bin/tshark", "-r", pcap_file, "-qz", "conv,ipv4"]
    udp_command = ["/usr/bin/tshark", "-r", pcap_file, "-qz", "conv,ipv6"]

    tcp_result = subprocess.run(tcp_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    udp_result = subprocess.run(udp_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    if tcp_result.returncode != 0:
        return f"Error: {tcp_result.stderr.strip()}"
    if udp_result.returncode != 0:
        return f"Error: {udp_result.stderr.strip()}"

    # Parse TCP and UDP results
    tcp_conversations = parse_conversations("TCP", tcp_result.stdout.splitlines())
    udp_conversations = parse_conversations("UDP", udp_result.stdout.splitlines())

    # Combine and apply limit before fetching locations
    all_conversations = sorted(tcp_conversations + udp_conversations, key=lambda x: x['Packets'], reverse=True)[:limit]

    # Collect unique public IPs from the top conversations
    unique_ips = {conv["IP A"] for conv in all_conversations}.union({conv["IP B"] for conv in all_conversations})

    # Fetch IP locations only for those in the final list
    ip_locations = {ip: get_ip_location(ip) for ip in unique_ips}

    # Dictionary to track used locations and apply jitter intelligently
    used_locations = {}

    # Function to add jitter dynamically
    def add_jitter(location, ip):
        if location:
            try:
                lat, lon = map(float, location.split(","))
                
                # Use a hash of the IP to generate a consistent jitter per IP
                hash_value = int(hashlib.md5(ip.encode()).hexdigest(), 16)  # Generate a hash from the IP
                jitter_range = 0.05  # Base jitter range

                # Generate offset using the hash, ensuring a small but distinct shift
                lat_offset = ((hash_value % 100) / 1000) * jitter_range
                lon_offset = (((hash_value // 100) % 100) / 1000) * jitter_range

                # Adjust if the location already exists
                while (lat + lat_offset, lon + lon_offset) in used_locations:
                    lat_offset += random.uniform(-jitter_range, jitter_range)
                    lon_offset += random.uniform(-jitter_range, jitter_range)

                # Store the new adjusted location
                used_locations[(lat + lat_offset, lon + lon_offset)] = ip
                return f"{lat + lat_offset},{lon + lon_offset}"

            except ValueError:
                return location
        return None

    # Append location and country data with jitter
    for conv in all_conversations:
        loc_a = ip_locations.get(conv["IP A"], {})
        loc_b = ip_locations.get(conv["IP B"], {})
        conv["IP A Loc"] = add_jitter(loc_a.get("location", None), conv["IP A"])
        conv["IP B Loc"] = add_jitter(loc_b.get("location", None), conv["IP B"])
        conv["IP A Country"] = loc_a.get("country", None)
        conv["IP B Country"] = loc_b.get("country", None)

    return json.dumps(all_conversations, indent=4)

# Example call
# get_top_conversations("/workspaces/pcap-visualizer-ed/PCAP-Visualizer/uploads/large_snort.pcap")
# print(get_top_conversations("/workspaces/pcap-visualizer-ed/PCAP-Visualizer/uploads/large_snort.pcap"))
