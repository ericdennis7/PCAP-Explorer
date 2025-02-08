import re
import json
import asyncio
import subprocess

def pcap_to_json(pcap_file):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # Path to TShark executable
    tshark_path = r"C:\Program Files\Wireshark\tshark.exe"

    # Path to your input pcap file
    input_pcap = r"C:\Users\ericd\Downloads\one_packet.pcap"  # Update this path to your actual .pcap file

    # Run TShark to print out the raw pcap content
    result = subprocess.run(
        [tshark_path, "-r", input_pcap, "-V"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    output = result.stdout.decode("utf-8")
    output_cleaned = "\n".join(line for line in output.splitlines() if line.strip())
    #print(output_cleaned)

    # Initialize lists to store the matched lines
    frame_matches = []
    four_space_matches = []
    eight_space_matches = []

    # Define patterns
    packet_start = r"^Frame \d+:.*"
    other_headers = r"^(?!Frame \d+: )\S.*"
    four_spaces = r"^ {4}(?! ).*"
    eight_spaces = r"^        (.*)"

    # Initialize an empty list to store the formatted results
    formatted_results = []
    inside_eight_space_list = False
    current_frame = None

    # Loop through each line and match with the patterns
    # Initialize an empty list to hold formatted strings
    formatted_results = []

    # Loop through each line and match with the patterns
    for line in output_cleaned.splitlines():
        frame_match = re.match(packet_start, line)
        other_headers_match = re.match(other_headers, line)
        four_space_match = re.match(four_spaces, line)
        eight_space_match = re.match(eight_spaces, line)

        # If the line matches the frame pattern, extract the frame number
        if frame_match:
            key, value = line.split(":", 1)
            formatted_line = f"""{{\n    'packet': {{\n        '{key.strip()}': '{value.strip()}' {{"""
            formatted_results.append(formatted_line)
        
        # If the line matches the other headers pattern, extract the key-value pairs
        elif other_headers_match:
            print(f"Matched other_header: {line}")
            stripped_line = line.strip()
            if ":" in stripped_line:
                key, value = line.split(":", 1)
                formatted_line = f"""        }}\n        '{key.strip()}': '{value.strip()}' {{"""
            else:
                formatted_line = f"""        '{stripped_line}' {{"""
            formatted_results.append(formatted_line)

        # If the line matches the four spaces pattern, extract the key-value pairs
        elif four_space_match:
            stripped_line = line.strip()
            if ":" in stripped_line:
                key, value = stripped_line.split(":", 1)
                formatted_line = f"""            '{key.strip()}': '{value.strip()}',"""
            else:
                formatted_line = f"""            '{stripped_line}',"""
            formatted_results.append(formatted_line)

        # If the line matches the eight spaces pattern, extract the key-value pairs
        elif eight_space_match:
            stripped_line = line.strip()
            if ":" in stripped_line:
                key, value = stripped_line.split(":", 1)
                formatted_line = f"""                '{key.strip()}': '{value.strip()}',"""
            else:
                formatted_line = f"""                '{stripped_line}'"""
            formatted_results.append(formatted_line)

    formatted_results.append("        }\n    }\n}")

    # Now join all the formatted results into a single string
    final_output = "\n".join(formatted_results)
    print(final_output)



# Now join all the formatted results into a single string
# final_output = "\n".join(formatted_results)
# print(final_output)


    # Print formatted results with indentation
    # for result in formatted_results:
    #     print(json.dumps(result, indent=4))

    # Loop through each line and match with corresponding patterns
    # for line in output_cleaned.splitlines():
    #     if re.match(packet_start, line):
    #         frame_matches.append(line)
    #     elif re.match(four_spaces, line) and not re.match(eight_spaces, line):
    #         four_space_matches.append(re.match(four_spaces, line).group(1))
    #     elif re.match(eight_spaces, line):
    #         eight_space_matches.append(re.match(eight_spaces, line).group(1))

    # # Printing the results
    # print("Frame Matches:")
    # print(frame_matches)
    # print("\nFour Space Matches:")
    # print(four_space_matches)
    # print("\nEight Space Matches:")
    # print(eight_space_matches)

    return None

# Example usage
pcap_file = "C:\\Users\\ericd\\Downloads\\dhcp.pcap"
packet_json = pcap_to_json(pcap_file)
