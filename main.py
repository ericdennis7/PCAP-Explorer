# Eric Dennis
# Started: 1/30/2025
# Description: This is a flask app that allows users to analyze their .pcap data with visuals and statistics.

# Last Updated: 1/30/2025
# Update Notes: Created the main.py file and added the basic flask app code.

# Imports
from flask import Flask, render_template

# Create the Flask app
app = Flask(__name__)

# Function to read the contents of imports.txt
def read_imports():
    try:
        with open("imports.txt", "r") as file:
            return file.read()
    except FileNotFoundError:
        return ""

# Route for the home page (index.html)
@app.route("/")
def index():
    imports = read_imports()
    return render_template("index.html", imports=imports)

if __name__ == "__main__":
    app.run(debug=True)