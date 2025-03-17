import csv
import hashlib
import requests
import humanize
import subprocess
import pandas as pd
from io import StringIO
from datetime import datetime
from collections import Counter, defaultdict

# Convert the .pcap file to DataFrame using TShark
def raw_pcap_pd(filepath):
    fields = [
        "frame.number",
        "frame.time",
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
        "udp.dstport",
        "frame.len",
        "frame.protocols"
    ]

    cmd = [
        "tshark", "-r", filepath, "-T", "fields",
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

    return df

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
        
        # Calculate time difference
        try:
            time_diff = end_dt - start_dt
            time_diff_humanized = humanize.naturaldelta(time_diff)
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

# Count of unique IPv4 and IPv6 addresses and flows, with combined IP count
def unique_ips_and_flows(df):
    unique_ipv4_set = set()
    unique_ipv6_set = set()
    unique_flows = set()
    ipv4_counts = Counter()
    ipv6_counts = Counter()

    try:
        for _, row in df.iterrows():
            src_ip = row.get("ip.src")
            dst_ip = row.get("ip.dst")
            src_ipv6 = row.get("ipv6.src")
            dst_ipv6 = row.get("ipv6.dst")
            
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
        return 0, 0, 0, 0, 0, 0, {}

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
def protocol_distribution(df, total_packets, csv_file="information-sheets/protocol-numbers.csv"):
    protocol_counts = {}
    protocol_mapping = load_protocol_mapping(csv_file)

    try:
        for _, row in df.iterrows():
            ip_layer = row.get("ip.src")
            ip_proto = row.get("ip.proto")

            # Get protocol name from CSV mapping, default to "Unknown"
            if ip_proto:
                protocol = protocol_mapping.get(ip_proto, "Unknown")
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

    # Calculate the percentage for each protocol (rounded to 2 decimals)
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
            # Check for TCP layer
            if "tcp.srcport" in row and "tcp.dstport" in row:
                src_port = row["tcp.srcport"]
                dst_port = row["tcp.dstport"]
            # Check for UDP layer
            elif "udp.srcport" in row and "udp.dstport" in row:
                src_port = row["udp.srcport"]
                dst_port = row["udp.dstport"]
            else:
                continue  # Skip non-TCP/UDP packets

            # Increment the count for each port
            if src_port:
                port_counts[src_port] += 1
            if dst_port:
                port_counts[dst_port] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

    # Calculate percentage based on ALL packets, not just TCP/UDP ones
    port_percentages = {
        port: round((count / (total_packets * 2)) * 100, 2) 
        for port, count in port_counts.items()
    }

    # Keep only the top 7 most frequent ports for display
    top_ports = dict(port_counts.most_common(7))

    return {"top_ports": top_ports, "port_percentages": port_percentages}

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

# Function to get the top 10 MAC addresses and their percentages, including OUI resolutions
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
        for mac, count in mac_counts.most_common(10)
    }

    return {"top_macs": mac_percentage}