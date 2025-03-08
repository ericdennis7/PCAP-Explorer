import os
import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

# URL to the website with the flags
url = "https://hatscripts.github.io/circle-flags/gallery"

# Folder where you want to save the flags
download_folder = r"C:\Users\ericd\OneDrive\Desktop\College\Capstone\PCAP-Visualizer\static\images\flags"

# Create the folder if it doesn't exist
os.makedirs(download_folder, exist_ok=True)

# Send a GET request to the website
response = requests.get(url)

# If the request was successful, proceed
if response.status_code == 200:
    # Parse the HTML content with BeautifulSoup
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all links to SVG files
    svg_links = soup.find_all('a', href=True)
    
    # Filter links to only those that end with .svg
    svg_links = [link['href'] for link in svg_links if link['href'].endswith('.svg')]

    # Download each SVG file
    for svg_link in svg_links:
        # Complete the URL in case the href is relative
        full_url = urljoin(url, svg_link)
        
        # Extract the filename from the URL
        filename = os.path.join(download_folder, os.path.basename(svg_link))

        # Send a GET request to download the SVG
        svg_response = requests.get(full_url)

        # If the request was successful, save the file
        if svg_response.status_code == 200:
            with open(filename, 'wb') as file:
                file.write(svg_response.content)
            print(f"Downloaded: {filename}")
        else:
            print(f"Failed to download: {full_url}")
else:
    print(f"Failed to retrieve the page: {url}")
