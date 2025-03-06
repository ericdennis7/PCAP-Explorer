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

# Function to get the top 10 MAC addresses
def mac_address_counts(packet_data):
    mac_counts = Counter()

    try:
        for packet in packet_data:
            layers = packet["_source"]["layers"]
            src_mac = layers.get("eth", {}).get("eth.src")
            dst_mac = layers.get("eth", {}).get("eth.dst")

            if src_mac:
                mac_counts[src_mac] += 1
            if dst_mac:
                mac_counts[dst_mac] += 1

    except Exception as e:
        print(f"Error processing packet: {e}")

    top_macs = dict(mac_counts.most_common(10))

    return {"top_macs": top_macs}

# Example usage
packet_data = raw_pcap_json("C:\\Users\\ericd\\Downloads\\newformat-large.pcapng")
print(mac_address_counts(packet_data))