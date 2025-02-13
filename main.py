# Eric Dennis
# Started: 1/30/2025
# Description: This is a flask app that allows users to analyze their .pcap data with visuals and statistics.

# Last Updated: 1/30/2025
# Update Notes: Created the main.py file and added the basic flask app code.

# Imports
import os
import humanize
from datetime import datetime
from flask import Flask, request, render_template, jsonify

# Function imports
from functions.data_extraction import *

app = Flask(__name__)

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
    return render_template("index.html", imports = imports)

# File Upload Route
@app.route("/success", methods=["POST"])
def success():

    # Check if a file was uploaded.
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    # Check if the file is a .pcap file. If not, return an error message.
    if file.filename == "" or not file.filename.endswith(".pcap"):
        return jsonify({"error": "Invalid file type. Only .pcap files are allowed."}), 400

    # Check if the file is too large. If so, return an error message.
    if request.content_length > 50 * 1024 * 1024:
        return jsonify({"error": "File too large. Max size is 50MB."}), 400
    
    file_md5 = md5_hash(file)

    # Save the uploaded .pcap file to the uploads folder.
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    file_name, file_extension = os.path.splitext(file.filename)
    new_filename = f"{file_name}_{current_datetime}{file_extension}"
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
    file.save(filepath)

    # Extract packet data
    packet_data = raw_pcap_json(filepath)

    try:
        # Collect file characteristics
        start_date, end_date, time_diff = packet_times_and_difference(packet_data)
        ip_count, ip_flow_count = unique_ips_and_flows(packet_data)
        
        file_info = {
            "name": file_name + file_extension,
            "size_mb": humanize.naturalsize(os.path.getsize(filepath)),  # MB
            "md5_hash": file_md5,
            "submission_date": datetime.now().strftime("%m/%d/%Y at %I:%M:%S %p").lstrip("0").replace("/0", "/"),
            "start_date": start_date,
            "end_date": end_date,
            "time_difference": time_diff,
            "total_packets": total_packets(packet_data),
            "unique_ip_addresses": ip_count,
            "unique_ip_flows": ip_flow_count
        }
    except Exception as e:
        return jsonify({"error": f"Error processing file: {str(e)}"}), 500

    except Exception as e:
        return jsonify({"error": f"Error processing file: {str(e)}"}), 500

    # Remove the uploaded .pcap file after processing
    os.remove(filepath)

    # Render the analysis.html template with extracted data
    imports = read_imports()
    return render_template("analysis.html", 
                           imports=imports, 
                           file_info=file_info, 
                           packet_data=packet_data)

# Run the app
if __name__ == "__main__":
    app.run(debug=True)