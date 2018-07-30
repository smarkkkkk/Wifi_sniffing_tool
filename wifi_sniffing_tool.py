import numpy as np
import pyshark
import math
import statistics
import csv
from scapy.all import *


def filter_packets_scapy(pcap_file):
    """
    This function loads a pcap file and filters all the packets

    :param: user selected pacp file number [pcap_file]
    :return: list of filtered packets [pkt_list]
    """

    # Read packets
    pcap_fn = 'pcap_files/'+pcap_dict[pcap_file]
    packets = rdpcap(pcap_fn)

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


def extract_packet_data_scapy(filtered_packets):
    """
    This function extracts data from the sniffed and filtered packets
    such as rssi, datarate, duration, antenna signal, ttl and seq

    :param: filtered_packets:
    :return:
    """
    pkt_data = np.zeros((len(filtered_packets), 4))
    pkt_incr = 0

    for pkt in filtered_packets:
        #off, radiotap = r.radiotap_parse(pkt)
        #print(radiotap)
        #print(pkt[0].show())
        #print(pkt[IP].ttl)
        #print(pkt[TCP].seq)
        #print(pkt.load)
        #print(codecs.getencoder(pkt.load))
        #print(pkt[RadioTap].present)
        #print(pkt[RadioTap].notdecoded)
        #print(pkt.radiotap.datarate)
        #print(ord(pkt.notdecoded[-2:-1]))
        #print(ord(pkt.notdecoded[-3:-2]))
        #print(ord(pkt.notdecoded[-5:-4]))

        try:
            extra = pkt.notdecoded
            rssi = -(256 - ord(extra[-4:-3]))  # ord returns an integer representing the Unicode code
        except:
            rssi = -100

        pkt_data[pkt_incr][0] = pkt_incr
        pkt_data[pkt_incr][1] = rssi  # rssi value is taken from unproven formula
        pkt_data[pkt_incr][2] = pkt[IP].ttl  # this value seems correct
        pkt_data[pkt_incr][3] = pkt[TCP].seq  # This is incorrect sequence

        pkt_incr += 1

    # pkt_data = pkt_data.astype(int)
    np.savetxt('data.csv', pkt_data, fmt='%1.10e', delimiter='\t')


def filter_packets_pyshark(pcap_file):
    """

    :param pcap_file:
    :return: pkt_list:
    """
    pcap_fn = 'pcap_files/' + pcap_dict[pcap_file]

    pkt_list = pyshark.FileCapture(pcap_fn, display_filter='(wlan.sa==00:25:9c:cf:8a:73 || wlan.sa==00:25:9c:cf:8a:71)'
                                                           '&&(wlan.da==40:c3:36:07:d4:bf||wlan.da==ff:ff:ff:ff:ff:ff)'
                                                           '&&!(wlan.fc.type==0)&&tcp')

    # packet_list = []
    # packet_list.append(pkt_list)
    # print(len(packet_list))
    return pkt_list


def extract_packet_data_pyshark(filtered_packets):
    """

    :param filtered_packets:
    :return: dbm_antsignal, datarate, duration, seq, ttl
    """
    # Initialise empty lists for packet features
    dbm_antsignal = [] # Received Signal Strength Indication RSSI
    datarate = []
    duration = []
    seq = []
    ttl = []

    # Extract all data from packets into lists
    for pkt in filtered_packets:
        dbm_antsignal.append(int(pkt.radiotap.dbm_antsignal))
        datarate.append(int(pkt.radiotap.datarate))
        duration.append(int(pkt.wlan.duration))
        seq.append(int(pkt.wlan.seq))
        ttl.append(int(pkt.ip.ttl))

    # Convert all packet feature lists to numpy arrays
    dbm_antsignal = np.asarray(dbm_antsignal)
    datarate = np.asarray(datarate)
    duration = np.asarray(duration)
    seq = np.asarray(seq)
    ttl = np.asarray(ttl)

    # Write all packet feature data to .csv file
    pkt_incr = 0
    pkt_data = np.zeros((len(dbm_antsignal), 5))

    while pkt_incr < len(dbm_antsignal):
        pkt_data[pkt_incr][0] = dbm_antsignal[pkt_incr]
        pkt_data[pkt_incr][1] = datarate[pkt_incr]
        pkt_data[pkt_incr][2] = duration[pkt_incr]
        pkt_data[pkt_incr][3] = seq[pkt_incr]
        pkt_data[pkt_incr][4] = ttl[pkt_incr]
        # print(dbm_antsignal[pkt_incr], datarate[pkt_incr], duration[pkt_incr], seq[pkt_incr], ttl[pkt_incr])
        pkt_incr += 1

    np.savetxt('data.csv', pkt_data, fmt='%1.10e', delimiter='\t')

    return dbm_antsignal, datarate, duration, seq, ttl


def live_capture():
    # may need to change interface string depending on what monitor mode interface appears from airmon-ng command
    capture = pyshark.LiveCapture(interface='wlan0mon', display_filter='(wlan.sa==00:25:9c:cf:8a:73 || '
                                                                       'wlan.sa==00:25:9c:cf:8a:71)'
                                                                       '&&(wlan.da==40:c3:36:07:d4:bf||'
                                                                       'wlan.da==ff:ff:ff:ff:ff:ff)'
                                                                       '&&!(wlan.fc.type==0)&&tcp')

    for pkt in capture.sniff_continuously(packet_count=200):
        print(pkt.radiotap.dbm_antsignal, pkt.radiotap.datarate, pkt.wlan.duration, pkt.wlan.seq, pkt.ip.ttl)


def feature_statistics(dbm_antsignal, datarate, duration, seq, ttl):
    print(dbm_antsignal, datarate, duration, seq, ttl)
    print(type(seq[1]))
    s = Statistics()
    print(s.mean(datarate))


# Possibly change Statistics to PacketAnalysis, PacketStats ?
class Statistics():

    # Not sure what needs to go in __init__ yet? Probably not mean and mode? Mean and mode need to be calculated
    # and then fed in as reference values for the new packets to be compared to. Maybe separate class for mean and mode
    # calculations and separate class for comparing new packet values to the mean and mode reference values.

    #def __init__(self, mean=0, mode=0, ref_val=0):
        #self.mean = mean
        #self.mode = mode
        #self.ref_val = ref_val

    def mean(self, data):
        """
        Returns the mean of the numbers
        :param nums:
        :return:
        """
        data = data[0:30]

        return statistics.mean(data)

    def mode(self, data):
        """
        Returns the mode of the numbers
        :param nums:
        :return:
        """
        data = data[0:30]

        return statistics.mode(data)

    def diff_from_ave(self, ref_val):
        """

        :param ref_val:
        :return:
        """


if __name__ == "__main__":
    # Allow user to decide whether to sniff in real time or load a pcap file
    while 1:
        print('1. Sniff packets online \n'
              '2. Load pcap file ')

        sniff_option = int(input('Select packet sniffing option: '))

        if sniff_option == 1:
            # Sniff packets in real time
            live_capture()
            break

        elif sniff_option == 2:

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
            # pkt_list = filter_packets_scapy(pcap_file_num)
            pkt_list = filter_packets_pyshark(pcap_file_num)

            print('All packets filtered. \n'
                  'Data is now being extracted from packets. \n')

            # Call function to extract relevant data from packets.
            # extract_packet_data_scapy(pkt_list)
            dbm_antsignal, datarate, duration, seq, ttl = extract_packet_data_pyshark(pkt_list)

            feature_statistics(dbm_antsignal, datarate, duration, seq, ttl)
            break

        else:
            print('Please enter either 1 or 2 from keyboard.')
