import subprocess
import pandas as pd
import json
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

# Example usage
packet_data = raw_pcap_json("C:\\Users\\ericd\\Downloads\\newformat-large.pcapng")
print(mac_address_counts(packet_data))