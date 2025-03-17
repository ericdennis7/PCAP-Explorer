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

import humanize
import subprocess
import pandas as pd
from io import StringIO

def raw_pcap_pd(filepath):
    fields = [
        "frame.number",
        "frame.time",
        "eth.src",
        "eth.dst",
        "eth.src.oui_resolved",
        "eth.dst.oui_resolved",
        "ip.src",
        "ipv6.src",
        "ip.dst",
        "ipv6.dst",
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

    return humanize.naturalsize(df.memory_usage(deep=True).sum())

# Example usage:
print(raw_pcap_pd("uploads/botnet-capture-20110810-neris.pcap"))