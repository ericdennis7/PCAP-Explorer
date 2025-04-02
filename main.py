# Eric Dennis
# Started: 1/30/2025
# Description: This is a flask app that allows users to analyze their .pcap(ng) data with visuals and statistics.

# Last Updated: 3/26/2025
# Update Notes: Changed loader, added L4 port distribution, and changed secret key to os.urandom(24).

# Dependencies
import os
import json
import time
import random
import humanize
import pandas as pd

from datetime import datetime
from werkzeug.middleware.proxy_fix import ProxyFix
from flask import Flask, request, render_template, jsonify, redirect, url_for, session, Response

# Data processing functions
from functions.data_extraction import *

# Creating Flask app & app settings
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024 * 1024
app.secret_key = os.urandom(24)

# Set upload directory
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# This route is used to render the index page
@app.route("/")
def index():
    return render_template("index.html")

# Initialize progress variable
progress = 0
status = "Uploading file"

# This route is used to upload files asynchronously and process them
@app.route("/upload", methods=["POST"])
def upload_file():
    """Handles AJAX file uploads asynchronously."""
    global progress, status
    time.sleep(1)
    
    progress = 0
    status = "Uploading file"
    
    # Check if a file was uploaded
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    # Check if the file is empty or not a .pcap or .pcapng file
    if file.filename == "" or not file.filename.endswith((".pcap", ".pcapng")):
        return jsonify({"error": "Invalid file type. Only .pcap or .pcapng files are allowed."}), 400

    if request.content_length > 50 * 1024 * 1024:
        return jsonify({"error": "File too large. Max size is 50MB."}), 400

    # Process the file
    try:
        status = "Validating file"
        progress = random.randint(1, 5)
        
        # Calculate MD5 hash of the file
        status = "Calculating file stats"
        file_md5 = md5_hash(file)
        progress =random.randint(11, 15)

        # Save the file to the upload folder
        current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        file_name, file_extension = os.path.splitext(file.filename)
        new_filename = f"{file_name}_{current_datetime}{file_extension}"
        filepath = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
        file.save(filepath)
        
        progress = random.randint(16, 20)
        status = "Extracting packet data"
        
        # Extract packet data from the file into JSON format
        packet_data = raw_pcap_pd(filepath)
        progress = random.randint(21, 35)
        status = "Analyzing timestamps"
        
        # Get packet times and time difference
        start_date, end_date, time_diff = packet_times_and_difference(packet_data)
        timing = group_packets_by_time_section(packet_data)
        progress = random.randint(36, 40)
        status = "Analyzing addresses and conversations"
        
        # Get total packets, calculate IP and MAC addresses, and top IP conversations
        packet_total = total_packets(packet_data)
        ipv4_addresses, ipv6_addresses, ipv4percent, ipv6percent, ip_count, unique_ip_addresses = unique_ips_and_flows(filepath)
        top_conversations = get_top_conversations(filepath)
        top_mac_addresses = mac_address_counts(packet_data)
        progress = random.randint(41, 65)
        status = "Analyzing flows"
        
        # Get TCP and UDP flow statistics
        tcp_min_flow, tcp_max_flow, tcp_avg_flow = tcp_min_max_avg(filepath)
        udp_min_flow, udp_max_flow, udp_avg_flow = udp_min_max_avg(filepath)
        progress = random.randint(66, 70)
        status = "Analyzing protocols and ports"

        # Get L4 and L7 protocol distributions
        l7_top_protocols, l7_protocol_percentages = application_layer_protocols(packet_data).values()
        l4_top_ports, l4_ports_percentages = transport_layer_ports(packet_data, packet_total).values()
        l4_top_protocols, l4_protocol_percentages = protocol_distribution(packet_data, packet_total).values()
        progress = random.randint(71, 90)
        status = "Performing Snort scan"

        # Get broken Snort rules, top source and destination IPs, and top rule ID
        snort_rules_json, snort_top_src_ip, snort_top_dst_ip, snort_top_rule_id, snort_priority_1_count, snort_priority_2_count, snort_priority_3_count = snort_rules(filepath)
        progress = random.randint(91, 99)
        status = "Preparing data"
        
        # Save analysis results into a JSON file
        file_info = {
            "name": file_name + file_extension,
            "data_link": new_filename.replace(".pcapng", "").replace(".pcap", "") + "_info.json",
            "size_mb": humanize.naturalsize(os.path.getsize(filepath)),
            "md5_hash": file_md5,
            "submission_date": datetime.now().strftime("%m/%d/%Y at %I:%M:%S %p").lstrip("0").replace("/0", "/"),
            "start_date": start_date,
            "end_date": end_date,
            "time_difference": time_diff,
            "total_packets": packet_total,
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
            "mac_addresses": top_mac_addresses,
            "time_series": timing,
            "snort_rules_json": json.loads(snort_rules_json),
            "snort_top_src_ip": snort_top_src_ip,
            "snort_top_dst_ip": snort_top_dst_ip,
            "snort_top_rule_id": snort_top_rule_id,
            "snort_priority_1_count": snort_priority_1_count,
            "snort_priority_2_count": snort_priority_2_count,
            "snort_priority_3_count": snort_priority_3_count,
            "top_conversations": json.loads(top_conversations)
        }

        # Save file data to JSON file
        file_data_folder = os.path.join(app.root_path, 'file_data')
        os.makedirs(file_data_folder, exist_ok=True)

        info_filename = f"{file_name}_{current_datetime}_info.json"
        info_filepath = os.path.join(file_data_folder, info_filename)
        with open(info_filepath, 'w', encoding='utf-8') as f:
            json.dump(file_info, f, indent=4)

        # Remove original file after processing
        os.remove(filepath)
        progress = 100
        status = "Uploading file"
        time.sleep(1)

        # Save file info path to session
        session['file_info'] = info_filepath

        # Redirect to the analysis page
        progress = 0
        return jsonify({"success": True, "redirect": url_for('analysis', filename=info_filename)})

    # Handle exceptions
    except Exception as e:
        progress = 0
        os.remove(filepath)

        return render_template("error.html", error_message=str(e)), 500

# This is the error page route
@app.route("/error")
def error():
    return render_template("error.html")

# This is the about page route
@app.route("/about")
def about():
    return render_template("about.html")

# This route is used to stream progress updates to the client
@app.route("/progress")
def progress_stream():
    """Provides real-time progress updates with status messages."""
    def stream():
        global progress, status
        while progress < 100:
            yield f"data: {json.dumps({'progress': progress, 'status': status})}\n\n"
            time.sleep(1)
        yield f"data: {json.dumps({'progress': 100, 'status': 'Upload Complete!'})}\n\n"

    return Response(stream(), mimetype='text/event-stream')

# This route is used to show a summary of the user's uploaded file
@app.route("/analysis/<filename>/summary")
def analysis(filename):
    file_info_path = os.path.join(app.root_path, 'file_data', filename)

    # Check if file exists before rendering the page
    if not os.path.exists(file_info_path):
        return redirect(url_for('index'))

    # Read file info from JSON
    with open(file_info_path, 'r', encoding='utf-8') as f:
        file_info = json.load(f)

    return render_template("analysis.html", file_info=file_info)

# This route is used to show the security analysis of the user's uploaded file using Snort
@app.route("/analysis/<filename>/security")
def security(filename):
    file_info_path = os.path.join(app.root_path, 'file_data', filename)

    # Check if file exists before rendering the page
    if not os.path.exists(file_info_path):
        return redirect(url_for('index'))

    # Read file info from JSON
    with open(file_info_path, 'r', encoding='utf-8') as f:
        file_info = json.load(f)

    return render_template("security.html", file_info=file_info)

# This route is used to show the address statistics of the user's uploaded file
@app.route("/analysis/<filename>/addresses")
def addresses(filename):
    file_info_path = os.path.join(app.root_path, 'file_data', filename)

    # Check if file exists before rendering the page
    if not os.path.exists(file_info_path):
        return redirect(url_for('index'))

    # Read file info from JSON
    with open(file_info_path, 'r', encoding='utf-8') as f:
        file_info = json.load(f)

    return render_template("addresses.html", file_info=file_info)


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

# Run the app using Flask development server
if __name__ == "__main__":
    app.run(debug=True)
