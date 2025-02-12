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

    return output_cleaned

# Example usage
pcap_file = "C:\\Users\\ericd\\Downloads\\dhcp.pcap"
packet_json = pcap_to_json(pcap_file)


    # #print(output_cleaned)

    # # Initialize lists to store the matched lines
    # frame_matches = []
    # four_space_matches = []
    # eight_space_matches = []

    # # Define patterns
    # packet_start = r"^Frame \d+:.*"
    # other_headers = r"^(?!Frame \d+: )\S.*"
    # four_spaces = r"^ {4}(?! ).*"
    # eight_spaces = r"^        (.*)"

    # # Initialize an empty list to store the formatted results
    # formatted_results = []

    # # Split the cleaned output into lines and iterate over them
    # lines = output_cleaned.splitlines()
    # for idx, line in enumerate(lines):
    #     frame_match = re.match(packet_start, line)
    #     other_headers_match = re.match(other_headers, line)
    #     four_space_match = re.match(four_spaces, line)
    #     eight_space_match = re.match(eight_spaces, line)

    #     # If the line matches the frame pattern, extract the frame number
    #     if frame_match:
    #         formatted_line = f"""{{\n    "packet": {{\n        "{line.strip()}": {{"""
    #         formatted_results.append(formatted_line)

    #     # If the line matches the other headers pattern, extract the key-value pairs
    #     elif other_headers_match:
    #         stripped_line = line.strip()
    #         if ":" in stripped_line:
    #             key, value = line.split(":", 1)
    #             formatted_line = f"""        }},\n        "{line.strip()}" {{"""
    #         else:
    #             formatted_line = f"""        "{stripped_line}" {{"""
                
    #         formatted_results.append(formatted_line)

    #     # If the line matches the four spaces pattern, extract the key-value pairs
    #     elif four_space_match:
    #         stripped_line = line.strip()

    #         # Check if the next line exists and is indented by 8 spaces
    #         if idx + 1 < len(lines) and re.match(eight_spaces, lines[idx + 1]):
    #             # Logic when the line *is* followed by an 8-space indented line
    #             if ":" in stripped_line:
    #                 key, value = stripped_line.split(":", 1)
    #                 formatted_line = f"""            "{key.strip()}": {{"""  # Prepare for nested key-value pairs
    #             else:
    #                 formatted_line = f"""            "{stripped_line}": {{"""  # Prepare for nested values
    #         else:
    #             # Logic when the line *is not* followed by an 8-space indented line
    #             if ":" in stripped_line:
    #                 key, value = stripped_line.split(":", 1)
    #                 formatted_line = f"""            "{key.strip()}": "{value.strip()}","""
    #             else:
    #                 formatted_line = f"""            "{stripped_line}","""

    #         formatted_results.append(formatted_line)

    # # If the line matches the eight spaces pattern, extract the key-value pairs
    #     elif eight_space_match:
    #         stripped_line = line.strip()

    #         # Check if the next line exists and is indented by 4 spaces
    #         if idx + 1 < len(lines) and re.match(four_spaces, lines[idx + 1]):
    #             # Logic when the line *is* followed by a 4-space indented line
    #             if ":" in stripped_line:
    #                 key, value = stripped_line.split(":", 1)
    #                 formatted_line = f"""                "{key.strip()}": "{value.strip()}","""
    #             else:
    #                 formatted_line = f"""                "{stripped_line}" """
                
    #             # Append the formatted line and close the block with a separate "}"
    #             formatted_results.append(formatted_line)
    #             formatted_results.append("            },")  # Closing brace aligned with 4-space indentation
    #         else:
    #             # Logic when the line *is not* followed by a 4-space indented line
    #             if ":" in stripped_line:
    #                 key, value = stripped_line.split(":", 1)
    #                 formatted_line = f"""                "{key.strip()}": "{value.strip()}","""
    #             else:
    #                 formatted_line = f"""                "{stripped_line}" """
                
    #             formatted_results.append(formatted_line)

    # formatted_results.append("        }\n    }\n}")

    # # Now join all the formatted results into a single string
    # final_output = "\n".join(formatted_results)
    # print(final_output)

    # json_output = json.loads(final_output)
    # print(type(json_output))

    # return None