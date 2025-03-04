import subprocess

def extract_min_max_avg(pcap_file):
    # Construct the tshark command to get flow statistics for TCP
    command = [
        'tshark', '-r', pcap_file, '-q', '-z', 'conv,tcp'
    ]
    
    # Run tshark command
    result = subprocess.run(command, capture_output=True, text=True)
    
    if result.returncode != 0:
        print("Error running tshark:", result.stderr)
        return
    
    # Process tshark output to remove headers, footer, and sort by bytes
    output = result.stdout
    lines = output.splitlines()

    # Skip the header lines (first 5) and the last footer line
    lines = lines[5:-1]

    # Extract the last value from each line (which is the time value)
    last_values = []
    for line in lines:
        last_value = line.split()[-1]  # Extract the last element from the split line
        last_values.append(float(last_value))  # Convert to float for calculations

    # Calculate min, max, and average
    if last_values:
        min_value = min(last_values)
        max_value = max(last_values)
        avg_value = sum(last_values) / len(last_values)
        
        # Print results
        print("Min:", min_value)
        print("Max:", max_value)
        print("Average:", f'{avg_value:.4f}')
    else:
        print("No valid data to process.")

# Example usage
pcap_file = "C:\\Users\\ericd\\Downloads\\newformat-large.pcapng"
extract_min_max_avg(pcap_file)
