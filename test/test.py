from credslayer import process_pcap

# Load the PCAP file
credentials = process_pcap("C:\\Users\\ericd\\Downloads\\large_pcap_test.pcapng").get_list_of_all_credentials()

print(credentials)
