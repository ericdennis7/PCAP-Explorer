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

import subprocess
from collections import Counter
import requests

def unique_ips_and_flows(pcap_file):
    # Full command to run tshark, tr, sort, and uniq
    command = f"tshark -r {pcap_file} -T fields -e ip.src -e ip.dst | tr '\\t' '\\n' | sort | uniq -c | sort -n"
    
    try:
        # Run the command with shell=True to allow pipes
        result = subprocess.run(command, shell=True, capture_output=True, text=True, check=True)
        ip_addresses = result.stdout.splitlines()  # Split the output by lines and return as a list of IP addresses
        
        # Process the IPs
        ipv4_counts = Counter()
        ipv6_counts = Counter()

        for line in ip_addresses:
            # Skip empty lines
            if not line.strip():
                continue
            
            parts = line.split(maxsplit=1)
            if len(parts) < 2:
                # Skip malformed lines
                continue
            
            count, ip = parts

            # Handle IPs
            if ':' in ip:  # Check if it's an IPv6 address
                ipv6_counts[ip] += int(count)
            else:  # Otherwise, treat it as an IPv4 address
                ipv4_counts[ip] += int(count)

        # Calculate the total counts and percentages
        total_ipv4_count = sum(ipv4_counts.values())
        total_ipv6_count = sum(ipv6_counts.values())
        combined_ip_count = total_ipv4_count + total_ipv6_count
        
        ipv4_percent = round((total_ipv4_count / combined_ip_count) * 100, 2) if combined_ip_count > 0 else 0
        ipv6_percent = round((total_ipv6_count / combined_ip_count) * 100, 2) if combined_ip_count > 0 else 0

        # Get the top 10 most frequent IPs
        top_ipv4_ips = dict(ipv4_counts.most_common(10))
        top_ipv6_ips = dict(ipv6_counts.most_common(10))

        # Combine both IPv4 and IPv6 top 10 IPs
        combined_top_ips = dict(sorted({**top_ipv4_ips, **top_ipv6_ips}.items(), key=lambda x: x[1], reverse=True)[:10])

        total_count = sum(combined_top_ips.values())

        top_ips_data = {
            ip: {
                "count": count,
                "percentage": (count / total_count) * 100 if total_count > 0 else 0
            }
            for ip, count in combined_top_ips.items()
        }

        # Fetch additional information about each IP (e.g., location)
        def probe_ip(ip):
            try:
                response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=2)
                if response.status_code == 200:
                    return response.json()
            except requests.RequestException:
                return {}
            return {}

        # Add location data to top IPs
        for ip in top_ips_data:
            ip_info = probe_ip(ip)
            if ip_info.get("bogon", False):
                ip_info.update({
                    "hostname": "bogon", "city": "", "region": "",
                    "country": "bogon", "loc": "bogon", "org": "bogon",
                    "postal": "bogon", "timezone": "bogon"
                })
            
            city = ip_info.get("city", "")
            region = ip_info.get("region", "")
            country = ip_info.get("country", "")
            ip_info["location"] = ", ".join(filter(None, [city, region, country]))  # Filters out empty values

            ip_info.update(top_ips_data[ip])
            top_ips_data[ip] = ip_info

        return len(ipv4_counts), len(ipv6_counts), ipv4_percent, ipv6_percent, combined_ip_count, {"top_ips": top_ips_data}

    except subprocess.CalledProcessError as e:
        print(f"Error running tshark: {e}")
        return 0, 0, 0, 0, 0, {}

print(unique_ips_and_flows("/workspaces/pcap-visualizer-ed/PCAP-Visualizer/uploads/church-traffic-sample.pcapng"))
