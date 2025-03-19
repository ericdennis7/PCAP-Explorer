# import os
# from flask import Flask, render_template, request
# from json import dumps

# app = Flask(__name__)

# # Directory path (change this to your desired directory)
# DIRECTORY_PATH = "C:\\Users\\ericd\\OneDrive\\Desktop\\College\\Capstone\\PCAP-Visualizer\\file_data"

# # Get a list of filenames in the directory
# def get_filenames():
#     try:
#         filenames = os.listdir(DIRECTORY_PATH)  # List all files in the directory
#         return [{'id': i, 'filename': filename} for i, filename in enumerate(filenames)]
#     except Exception as e:
#         print(f"Error reading directory: {e}")
#         return []

# # Dummy data (you can replace this with filenames)
# files = get_filenames()

# @app.route('/')
# def index():
#     return render_template('basic-table.html', users=dumps(files))

# @app.route('/default')
# def default():
#     return render_template('default-table.html', users=dumps(files))

# @app.route('/server')
# def server():
#     return render_template('server-table.html')

# @app.route('/api/data')
# def api_data():
#     try:
#         # Fetch search, sort, pagination params
#         search = request.args.get('search')
#         sort = request.args.get('sort', 'filename')
#         direction = request.args.get('dir', 'asc')
#         start = request.args.get('start', type=int, default=0)
#         length = request.args.get('length', type=int, default=10)

#         # Get filenames
#         filtered_files = files

#         # Search functionality
#         if search != 'undefined' and search:
#             search = search.lower()
#             filtered_files = [
#                 file for file in files
#                 if search in file['filename'].lower()
#             ]

#         # Sorting functionality
#         if sort != 'undefined' and sort != '':
#             sort_key = sort.lower()
#             reverse = direction == 'desc'
#             filtered_files.sort(key=lambda x: x[sort_key], reverse=reverse)

#         # Pagination functionality
#         paginated_files = filtered_files[start:start + length]

#         return {
#             'data': paginated_files,
#             'total': len(filtered_files)
#         }

#     except Exception as e:
#         print(e)
#         return {'error': str(e)}

# if __name__ == '__main__':
#     app.run(debug=True)

import subprocess
import pandas as pd
import matplotlib.pyplot as plt
from io import StringIO

def raw_pcap_pd(filepath):
    fields = [
        "frame.number",
        "frame.time",
        "frame.time_epoch",
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
    
    # Convert relevant fields to integers where possible
    fields_to_convert = [
        "ip.proto",
        "tcp.srcport", "tcp.dstport",
        "udp.srcport", "udp.dstport"
    ]

    for field in fields_to_convert:
        if field in df.columns:
            df[field] = pd.to_numeric(df[field], errors="coerce").astype("Int64")

    return df

# Load the pcap data
df = raw_pcap_pd("/workspaces/pcap-visualizer-ed/PCAP-Visualizer/uploads/botnet-capture-20110810-neris.pcap")

def group_packets_by_time_section(df, num_sections=10):
    # Convert frame.time_epoch to numeric if not already
    df['frame.time_epoch'] = pd.to_numeric(df['frame.time_epoch'], errors='coerce')

    # Find the min and max of frame.time_epoch
    min_time = df['frame.time_epoch'].min()
    max_time = df['frame.time_epoch'].max()

    # Calculate the interval size based on the number of sections
    interval_size = (max_time - min_time) / num_sections

    # Create the time sections (intervals)
    time_sections = [(min_time + i * interval_size, min_time + (i + 1) * interval_size) for i in range(num_sections)]

    # Group packets by time section and calculate the packet count and total bytes for each section
    section_counts = {
        f"Section {i+1} ({start}-{end} sec)": {
            "packet_count": len(df[(df['frame.time_epoch'] >= start) & (df['frame.time_epoch'] < end)]),
            "total_bytes": df[(df['frame.time_epoch'] >= start) & (df['frame.time_epoch'] < end)]['frame.len'].sum()
        }
        for i, (start, end) in enumerate(time_sections)
    }

    return section_counts