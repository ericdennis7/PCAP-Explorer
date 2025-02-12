import subprocess

# Path to TShark executable
tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

# Path to your input pcap file
input_pcap = r"C:\Users\ericd\Downloads\dhcp.pcap"  # Update this path to your actual .pcap file

# Run TShark to print out the raw pcap content in verbose mode
result = subprocess.run(
    [tshark_path, "-r", input_pcap, "-T", "json"],
    stdout=subprocess.PIPE,
    stderr=subprocess.PIPE
)

# Convert the result to a string
output = result.stdout.decode("utf-8")
print(output)

# # Function to generate HTML structure with collapsible sections
# def create_html_from_tshark_output(raw_output):
#     html_content = """
#     <html>
#     <head>
#         <style>
#             .collapsible {
#                 background-color: #777;
#                 color: white;
#                 cursor: pointer;
#                 padding: 10px;
#                 width: 100%;
#                 border: none;
#                 text-align: left;
#                 outline: none;
#                 font-size: 15px;
#             }

#             .active, .collapsible:hover {
#                 background-color: #555;
#             }

#             .content {
#                 padding: 0 18px;
#                 display: none;
#                 overflow: hidden;
#                 background-color: #f1f1f1;
#             }
#         </style>
#     </head>
#     <body>
#     <h2>Packet Details</h2>
#     <button class="collapsible">Click to view the packet details</button>
#     <div class="content">
#         <pre>"""
    
#     # Split the output into lines and process each line to create collapsible sections
#     lines = raw_output.splitlines()
#     for line in lines:
#         if line.strip():  # If the line is not empty
#             html_content += f'<button class="collapsible">{line}</button><div class="content"><pre>{line}</pre></div>'
    
#     html_content += """
#         </pre>
#     </div>
#     <script>
#         var coll = document.getElementsByClassName("collapsible");
#         for (var i = 0; i < coll.length; i++) {
#             coll[i].addEventListener("click", function() {
#                 this.classList.toggle("active");
#                 var content = this.nextElementSibling;
#                 if (content.style.display === "block") {
#                     content.style.display = "none";
#                 } else {
#                     content.style.display = "block";
#                 }
#             });
#         }
#     </script>
#     </body>
#     </html>
#     """
    
#     return html_content

# # Create HTML content from the TShark output
# html_result = create_html_from_tshark_output(output)

# # Write the HTML result to a file
# output_html_file = "packet_details.html"
# with open(output_html_file, "w") as file:
#     file.write(html_result)

# print(f"HTML file created: {output_html_file}")
