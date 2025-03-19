# Eric Dennis
# Started: 1/30/2025
# Description: This is a flask app that allows users to analyze their .pcap data with visuals and statistics.

# Last Updated: 2/25/2025
# Update Notes: Changed loader, added L4 port distribution, and changed secret key to os.urandom(24).

# Imports
import os
import json
import humanize
import pandas as pd

from datetime import datetime
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, request, render_template, jsonify, redirect, url_for, session

# Function imports
from functions.data_extraction import *

# Creating Flask app & app settings
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 * 1024
app.secret_key = os.urandom(24)

# Set upload directory
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Function to read imports.txt
def read_imports():
    try:
        with open("imports.txt", "r") as file:
            return file.read()
    except FileNotFoundError:
        return ""

# Index Page
@app.route("/")
def index():
    imports = read_imports()
    return render_template("index.html", imports=imports)

# Upload route
@app.route("/upload", methods=["POST"])
def upload_file():
    """Handles AJAX file uploads asynchronously."""
    
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    # Validate file type and size
    if file.filename == "" or not file.filename.endswith((".pcap", ".pcapng")):
        return jsonify({"error": "Invalid file type. Only .pcap or .pcapng files are allowed."}), 400

    if request.content_length > 50 * 1024 * 1024 * 1024:  # 50MB limit
        return jsonify({"error": "File too large. Max size is 50MB."}), 400

    try:
        # Save the uploaded file
        file_md5 = md5_hash(file)
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name, file_extension = os.path.splitext(file.filename)
        new_filename = f"{file_name}_{current_datetime}{file_extension}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
        file.save(filepath)

        # Extract packet data
        packet_data = raw_pcap_pd(filepath)

        # Collect file characteristics
        start_date, end_date, time_diff = packet_times_and_difference(packet_data)
        packet_total = total_packets(packet_data)
        ipv4_addresses, ipv6_addresses, ipv4percent, ipv6percent, ip_count, unique_ip_addresses = unique_ips_and_flows(filepath)
        tcp_min_flow, tcp_max_flow, tcp_avg_flow = tcp_min_max_avg(filepath)
        udp_min_flow, udp_max_flow, udp_avg_flow = udp_min_max_avg(filepath)
        l7_top_protocols, l7_protocol_percentages = application_layer_protocols(packet_data).values()
        l4_top_ports, l4_ports_percentages = transport_layer_ports(packet_data, packet_total).values()
        l4_top_protocols, l4_protocol_percentages = protocol_distribution(packet_data, packet_total).values()

        file_info = {
            "name": file_name + file_extension,
            "size_mb": humanize.naturalsize(os.path.getsize(filepath)),
            "md5_hash": file_md5,
            "submission_date": datetime.now().strftime("%m/%d/%Y at %I:%M:%S %p").lstrip("0").replace("/0", "/"),
            "start_date": start_date,
            "end_date": end_date,
            "time_difference": time_diff,
            "total_packets": total_packets(packet_data),
            "ipv4": ipv4_addresses,
            "ipv4percent": ipv4percent,
            "ipv6": ipv6_addresses,
            "ipv6percent": ipv6percent,
            "unique_ips": unique_ip_addresses,
            "unique_ip_addresses": ip_count,
            "tcp_min_flow": tcp_min_flow,
            "tcp_max_flow": tcp_max_flow,
            "tcp_avg_flow": tcp_avg_flow,
            "udp_min_flow": udp_min_flow,
            "udp_max_flow": udp_max_flow,
            "udp_avg_flow": udp_avg_flow,
            "l4_top_protocols": l4_top_protocols,
            "l4_protocol_percentages": l4_protocol_percentages,
            "l4_top_ports": l4_top_ports,
            "l4_ports_percentages": l4_ports_percentages,
            "l7_top_protocols": l7_top_protocols,
            "l7_protocol_percentages": l7_protocol_percentages,
            "mac_addresses": mac_address_counts(packet_data),
            "time_series": group_packets_by_time_section(packet_data)
        }

        # Create `file_data` folder if it doesn't exist
        file_data_folder = os.path.join(app.root_path, 'file_data')
        os.makedirs(file_data_folder, exist_ok=True)

        # Store file info as JSON in `file_data`
        info_filename = f"{file_name}_{current_datetime}_info.json"
        info_filepath = os.path.join(file_data_folder, info_filename)
        with open(info_filepath, 'w', encoding='utf-8') as f:
            json.dump(file_info, f, indent=4)

        # Remove original file after processing
        os.remove(filepath)

        # Save file references in session
        session['file_info'] = info_filepath

        # Return a response with a redirect URL (includes filename)
        return jsonify({
            "success": True, 
            "redirect": url_for('analysis', filename=f"{file_name}_{current_datetime}_info.json")
        })

    except Exception as e:

        # Remove original file after processing
        os.remove(filepath)

        return jsonify({"error": f"Error processing file: {str(e)}"}), 500


# Analysis Page
@app.route("/analysis/<filename>/summary")
def analysis(filename):
    file_info_path = os.path.join(app.root_path, 'file_data', filename)

    # Check if file exists before rendering the page
    if not os.path.exists(file_info_path):
        return redirect(url_for('index'))

    # Read file info from JSON
    with open(file_info_path, 'r', encoding='utf-8') as f:
        file_info = json.load(f)

    imports = read_imports()

    # Pass only file_info to the template
    return render_template("analysis.html", file_info=file_info, imports=imports)


# @app.route('/api/pcap_data', methods=['GET'])
# def pcap_data():
#     pcap_file = "C:\\Users\\ericd\\Downloads\\capture.pcap"
    
#     # Get data from pcap function
#     data = pcap_packet_summaries(pcap_file)

#     # Get the search value from DataTables
#     search_value = request.args.get('search[value]', '').lower()

#     # Filter the data based on the search query
#     if search_value:
#         data = [item for item in data if any(search_value in str(value).lower() for value in item.values())]

#     # DataTables request parameters
#     start = int(request.args.get('start', 0))  # The starting index for data
#     length = int(request.args.get('length', 10))  # The page length

#     # Pagination: slice the data to return only the required portion
#     paginated_data = data[start:start + length]
    
#     # Return the data in the format DataTables expects
#     return jsonify({
#         'draw': int(request.args.get('draw', 0)),  # Incrementing number sent by DataTables
#         'recordsTotal': len(data),  # Total number of records
#         'recordsFiltered': len(data),  # Number of records after filtering
#         'data': paginated_data  # Data to display on the current page
#     })

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
