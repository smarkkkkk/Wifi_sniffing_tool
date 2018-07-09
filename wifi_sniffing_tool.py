import numpy
from scapy.all import *


def filter_packets(pcap_file):
    """
    This function loads a pcap file and filters all the packets

    :param: user selected pacp file number [pcap_file]
    :return: list of filtered packets [pkt_list]
    """
    # Read packets
    packets = rdpcap(pcap_dict[pcap_file])

    print('pcap file read successfully \n')

    pkt_count = 0
    management_count = 0
    src_count = 0
    dst_count = 0
    tcp_count = 0
    pkt_list = []

    # Implement filter
    for pkt in packets:
        if not pkt.type == 0:  # Removes management packets
            management_count += 1
            if pkt.haslayer(TCP):  # Only process TCP packets
                tcp_count += 1
                if pkt.addr2 == "00:25:9c:cf:8a:73" or pkt.addr2 == "00:25:9c:cf:8a:71":  # Souce MAC
                    src_count += 1
                    if pkt.addr3 == "00:25:9c:cf:8a:73" or pkt.addr3 == "00:25:9c:cf:8a:71":  # Destination MAC
                        dst_count += 1
                        pkt_count += 1
                        pkt_list.append(pkt)

    print('Number of packets found for each filter stage: \n'
          'Non management packets = {} \n'
          'TCP packets = {}\n'
          'Correct source address = {}\n'
          'Correct destination address = {}\n'
          'Final number of packets = {}\n'.format(management_count, tcp_count, src_count, dst_count, pkt_count))

    return pkt_list


def extract_packet_data(filtered_packets):
    """
    This function extracts data from the sniffed and filtered packets
    such as rssi, datarate, duration, antenna signal, ttl and seq

    :param: packets:
    :return:
    """

    for pkt in filtered_packets:
        # print(pkt.dBm_AntSignal)
        try:
            extra = pkt.notdecoded
            rssi = -(256 - ord(extra[-4:-3]))
        except:
            rssi = -100

        # print('WiFi signal strength: {}'.format(rssi))


if __name__ == "__main__":
    # Lookup dict for different pcap files
    pcap_dict = {'1': 'variable_rate_normal_mon_VP',
                 '2': 'variable_rate_attack01_mon_VP',
                 '3': 'variable_rate_attack02_mon_VP',
                 '4': 'variable_rate_inthemix_mon_VP'}

    # Menu of options for which pcap file to process
    print('1. variable_rate_normal_mon_VP \n'
          '2. variabel_rate_attack01_mon_VP \n'
          '3. variable_rate_attack02_mon_VP \n'
          '4. variable_rate_inthemix_mon_VP')

    pcap_file_num = str(input('Enter pcap file no. to use: '))

    # Call function to filter all packets.
    pkt_list = filter_packets(pcap_file_num)

    print('All packets filtered. \n'
          'Data is now being extracted from packets. \n')

    # Call function to extract relevant data from packets.
    extract_packet_data(pkt_list)

    if "00:25:9c:cf:8a:73" == "00:25:9c:cf:8a:71":
        print('MAC filter not working')










