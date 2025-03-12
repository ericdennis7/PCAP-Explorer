from credslayer import process_pcap

if __name__ == "__main__":
    credentials = process_pcap("C:\\Users\\ericd\\Downloads\\ftp.pcap").get_list_of_all_credentials()

    print(credentials)