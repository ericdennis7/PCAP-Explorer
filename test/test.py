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

import re
import subprocess
import json

def parse_snort_output(pcap_filename):
    # Run the Snort command and capture its output
    command = [
        "sudo", "snort", "-q", "-r", pcap_filename, "-c", "/etc/snort/snort.conf", "-A", "console"
    ]

    # Run Snort command and capture stdout
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    # Get the Snort output from stdout
    snort_output = result.stdout

    # Regular expression pattern to capture each part
    pattern = re.compile(r'(?P<Date>\d{2}/\d{2})-(?P<Time>\d{2}:\d{2}:\d{2}\.\d+)  \[\*\*] \[(?P<RuleID>\d+:\d+:\d+)\] (?P<Message>.*?) \[\*\*] \[Classification: (?P<Classification>.*?)\] \[Priority: (?P<Priority>\d+)\] \{(?P<Protocol>\w+)\} (?P<Source>[\d\.\:]+) -> (?P<Dest>[\d\.\:]+)')

    # List to store parsed data
    data = []

    # Parse each log entry in the Snort output
    for log in snort_output.splitlines():
        match = pattern.match(log)
        if match:
            # Directly extract Source and Dest as they are
            log_data = match.groupdict()
            data.append(log_data)

    # Convert list to JSON
    json_output = json.dumps(data, indent=4)

    # Return JSON output
    return json_output

# Example usage
pcap_filename = "/workspaces/pcap-visualizer-ed/PCAP-Visualizer/uploads/botnet-capture-20110810-neris.pcap"
json_output = parse_snort_output(pcap_filename)

# Print JSON output
print(json_output)

