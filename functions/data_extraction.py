# This file extracts data from a .pcap file for statistical analysis.
import json
import subprocess
from datetime import datetime

def raw_pcap_json(filepath):

    # Path to TShark executable
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

    # Path to your input pcap file
    input_pcap = filepath  # Update this path to your actual .pcap file

    # Run TShark to print out the raw pcap content in verbose mode
    result = subprocess.run(
        [tshark_path, "-r", input_pcap, "-T", "json"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    # Convert the result to a string
    output = result.stdout.decode("utf-8")

    # Parse the JSON output
    try:
        packet_data = json.loads(output)  # Parse JSON into Python object (list or dict)
        return packet_data
    except json.JSONDecodeError:
        raise Exception("Error decoding JSON from TShark output")

# Extract the start date from the packet data
def start_date(packet_data):
    try:
        date = "Dec  5, 2004 14:16:24.317453000 Eastern Standard Time"
        
        # Remove the timezone and fix microseconds length
        date_part = " ".join(date.split()[:-3])  # Remove "Eastern Standard Time"
        date_part = date_part[:date_part.find(".") + 7]  # Keep only 6 microseconds digits

        dt = datetime.strptime(date_part, "%b %d, %Y %H:%M:%S.%f")
        formatted_date = dt.strftime("%m/%d/%Y at %I:%M:%S %p").lstrip("0").replace("/0", "/")
        return formatted_date
    except KeyError:
        return "Start date not found in packet data"