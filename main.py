# Eric Dennis
# Started: 1/30/2025
# Description: This is a flask app that allows users to analyze their .pcap data with visuals and statistics.

# Last Updated: 1/30/2025
# Update Notes: Created the main.py file and added the basic flask app code.

# Imports
import os
from datetime import datetime
from flask import Flask, request, render_template, jsonify

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
    # Check if file was uploaded
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]

    # Check if file is empty or not a .pcap file
    if file.filename == "" or not file.filename.endswith(".pcap"):
        return jsonify({"error": "Invalid file type. Only .pcap files are allowed."}), 400

    # Check if file is too large
    if request.content_length > 50 * 1024 * 1024:
        return jsonify({"error": "File too large. Max size is 50MB."}), 400

    # Get the current date and time, formatted as "YYYY-MM-DD_HH:MM:SS"
    current_datetime = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    
    # Split the original filename into name and extension
    file_name, file_extension = os.path.splitext(file.filename)

    # Create a new filename by appending the current date and time
    new_filename = f"{file_name}_{current_datetime}{file_extension}"

    # Save the file with the new filename
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], new_filename)
    file.save(filepath)

    # Redirect to analysis page
    imports = read_imports()
    return render_template("analysis.html", name=new_filename, imports=imports)

# Run the app
if __name__ == "__main__":
    app.run(debug=True)