# This file extracts data from a .pcap file for statistical analysis.
import csv
import json
import hashlib
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
    
# Function to count L7 protocols
def application_layer_protocols(packet_data):
    protocol_counts = defaultdict(int)

    for packet in packet_data:
        layers = packet["_source"]["layers"]

        # Extract IPv4 source and destination
        protocols = layers.get("frame", {}).get("frame.protocols", "")

        protocol_list = protocols.split(":")

        if len(protocol_list) >= 5:
            l7_protocol = protocol_list[4]
            protocol_counts[l7_protocol] += 1

    return dict(protocol_counts)

packet_data = raw_pcap_json("C:\\Users\\ericd\\Downloads\\http-chunked-gzip.pcap")
print(application_layer_protocols(packet_data))