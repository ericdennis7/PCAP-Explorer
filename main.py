# Eric Dennis
# Started: 1/30/2025
# Description: This is a flask app that allows users to analyze their .pcap data with visuals and statistics.

# Last Updated: 2/14/2025
# Update Notes: Implemented AJAX-based file upload processing.

# Imports
import os
import humanize

import tempfile
import json

from datetime import datetime
from flask import Flask, request, render_template, jsonify, redirect, url_for, session

# Function imports
from functions.data_extraction import *

app = Flask(__name__)
app.secret_key = "your_secret_key"

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

@app.route("/upload", methods=["POST"])
def upload_file():
    """Handles AJAX file uploads asynchronously."""
    
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    # Validate file type and size
    if file.filename == "" or not file.filename.endswith((".pcap", ".pcapng")):
        return jsonify({"error": "Invalid file type. Only .pcap or .pcapng files are allowed."}), 400

    if request.content_length > 50 * 1024 * 1024:  # 50MB limit
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
        packet_data = raw_pcap_json(filepath)

        # Collect file characteristics
        start_date, end_date, time_diff = packet_times_and_difference(packet_data)
        ip_count, ipv4_addresses, ipv6_addresses, ip_flow_count = unique_ips_and_flows(packet_data)
        l4_port_counts = transport_layer_ports(packet_data)
        l4_src_port_counts = l4_port_counts["top_source_ports"]
        l4_dst_port_counts = l4_port_counts["top_destination_ports"]
    
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
            "ipv6": ipv6_addresses,
            "unique_ip_addresses": ip_count,
            "unique_ip_flows": ip_flow_count,
            "protocols": protocol_distribution(packet_data),
            "l4_src_ports": l4_src_port_counts,
            "l4_dst_ports": l4_dst_port_counts
        }

        print(file_info["l4_src_ports"])
        print(file_info["l4_dst_ports"])

        # Store packet data in a temporary file
        temp_file = tempfile.NamedTemporaryFile(delete=False, mode='w', encoding='utf-8')
        temp_file_name = temp_file.name
        with open(temp_file_name, 'w', encoding='utf-8') as f:
            json.dump(packet_data, f)

        # Remove file after processing
        # os.remove(filepath)

        # Store the file reference in session (store the temp file name)
        session['file_info'] = file_info
        session['packet_data_file'] = temp_file_name

        # Return a response with a redirect URL
        return jsonify({"success": True, "redirect": url_for('analysis')})

    except Exception as e:
        return jsonify({"error": f"Error processing file: {str(e)}"}), 500


# Analysis Page
@app.route("/analysis")
def analysis():
    file_info = session.get('file_info')
    packet_data_file = session.get('packet_data_file')

    # Make sure the data exists in session before rendering the page
    if not file_info or not packet_data_file:
        return redirect(url_for('index'))

    # Read packet data from the temporary file
    with open(packet_data_file, 'r', encoding='utf-8') as f:
        packet_data = json.load(f)

    # Optional: Remove the temporary file after reading
    # os.remove(packet_data_file)

    imports = read_imports()
    return render_template("analysis.html", file_info=file_info, packet_data=packet_data, imports=imports)

# Run the app
if __name__ == "__main__":
    app.run(debug=True)
