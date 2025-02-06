from scapy.all import rdpcap
import json

import pyshark
import json
    
def pcap_to_json(pcap_file):
    capture = pyshark.FileCapture(pcap_file)
    packets_data = []

    for packet in capture:
        packet_data = {}
        for layer in packet.layers:
            packet_data[layer.layer_name] = layer._all_fields
        packets_data.append(packet_data)

    return packet_data
