# Eric Dennis
# Started: 1/30/2025
# Description: This is a flask app that allows users to analyze their .pcap data with visuals and statistics.

# Last Updated: 1/30/2025
# Update Notes: Created the main.py file and added the basic flask app code.

# Imports
from flask import Flask, request, render_template, jsonify
import os

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

# Home Page
@app.route("/")
def index():
    imports = read_imports()
    return render_template("index.html", imports = imports)

# File Upload Route
@app.route("/success", methods=["GET", "POST"])
def success():
    if request.method == "POST":
        if "file" not in request.files:
            return jsonify({"error": "No file uploaded"}), 400

        file = request.files["file"]

        if file.filename == "" or not file.filename.endswith(".pcap"):
            return jsonify({"error": "Invalid file type. Only .pcap files are allowed."}), 400

        if request.content_length > 50 * 1024 * 1024:  # 50MB limit
            return jsonify({"error": "File too large. Max size is 50MB."}), 400

        filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
        file.save(filepath)

        imports = read_imports()
        return render_template("analysis.html", name=file.filename, imports=imports)
    else:
        # Handle GET method for the page load if needed
        return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)