import pyshark
import json
import asyncio

def pcap_to_json(pcap_file):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    capture = pyshark.FileCapture(pcap_file)
    packets_data = []

    for packet in capture:
        packet_data = {}
        for layer in packet.layers:
            packet_data[layer.layer_name] = layer._all_fields
        packets_data.append(packet_data)
    
    capture.close()
    loop.close()

    return json.dumps(packets_data, indent=4)
