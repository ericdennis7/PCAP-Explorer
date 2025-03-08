import subprocess
import requests
import pandas as pd
import json
import myipaddress as myip
from collections import Counter, defaultdict

# Function to read the pcap file
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

def analyze_packet_data(packet_data):
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
        
        combined_ip_count = len(unique_ipv4_set) + len(unique_ipv6_set)
        combined_top_ips = dict(ipv4_counts.most_common(10))
        combined_top_ips.update(dict(ipv6_counts.most_common(10)))
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
                response = requests.get(f"https://ipinfo.io/{ip}/json")
                if response.status_code == 200:
                    return response.json()
            except requests.RequestException:
                return {}
            return {}
        
        for ip in top_ips_data:
            ip_info = probe_ip(ip)
            if ip_info.get("bogon", False):
                ip_info.update({
                    "hostname": "bogon", "city": "bogon", "region": "bogon",
                    "country": "bogon", "loc": "bogon", "org": "bogon",
                    "postal": "bogon", "timezone": "bogon"
                })
            ip_info.update(top_ips_data[ip])
            top_ips_data[ip] = ip_info
        
        return len(unique_ipv4_set), len(unique_ipv6_set), combined_ip_count, len(unique_flows), {"top_ips": top_ips_data}
    
    except KeyError:
        return 0, 0, 0, 0, {}

# Example usage
packet_data = []  # Replace with actual packet data
packet_data = raw_pcap_json("C:\\Users\\ericd\\Downloads\\test.pcap")
results = analyze_packet_data(packet_data)
print(json.dumps(results, indent=4))