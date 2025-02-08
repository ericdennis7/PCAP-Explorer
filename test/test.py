import subprocess
import json

# Path to TShark executable
tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

# Path to your input pcap file
input_pcap = r"C:\Users\ericd\Downloads\dhcp.pcap"  # Update this path to your actual .pcap file

# Run TShark to print out the raw pcap content in JSON format
result = subprocess.run(
    [tshark_path, "-r", input_pcap, "-V"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Convert the result to a string
output = result.stdout.decode("utf-8")
print(output)