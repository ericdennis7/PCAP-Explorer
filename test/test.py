import subprocess
import pandas as pd
import json

# Get packet summaries from a .pcap file
def pcap_packet_summaries(pcap_file):
    # Construct the tshark command to extract the required fields
    command = [
        'tshark', '-r', pcap_file, '-T', 'fields',
        '-e', 'frame.time',        # Timestamp
        '-e', 'frame.protocols',    # Frame Protocols
        '-e', 'ip.src',                  # Source IP
        '-e', 'tcp.srcport',             # Source Port
        '-e', 'ip.dst',                  # Destination IP
        '-e', 'tcp.dstport',             # Destination Port
        '-e', 'eth.src',                 # Source MAC
        '-e', 'eth.dst',                 # Destination MAC
        '-e', 'frame.len'                # Packet Size
    ]
    
    # Run tshark command
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error running tshark:", result.stderr)
        return
    
    # Initialize a list to hold all packet data
    data = []

    # Add column headers as the first row
    data.append([
        "Timestamp", "Protocols", "Source IP", "Source Port", 
        "Destination IP", "Destination Port", "Source MAC", "Destination MAC", "Packet Size"
    ])

    print(data)

    # Process output and store the result as a list of lists
    for line in result.stdout.splitlines():
        fields = line.split('\t')  # Tshark separates fields with tab characters
        if len(fields) == 9:
            data.append(fields)

    # Return the list of lists
    return data

# Example usage
pcap_file = "C:\\Users\\ericd\\Downloads\\newformat-large.pcapng"
print(pcap_packet_summaries(pcap_file))