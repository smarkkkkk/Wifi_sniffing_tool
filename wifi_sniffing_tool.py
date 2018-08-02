import numpy as np
import pyshark
import time
import argparse
import statistics
import os
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


def filter_packets_pyshark(pcap_fn):
    """

    :param pcap_fn:
    :return: pkt_list:
    """
    try:
        pkt_list = pyshark.FileCapture(pcap_fn, display_filter='(wlan.sa==00:25:9c:cf:8a:73 || '
                                                               'wlan.sa==00:25:9c:cf:8a:71) && '
                                                               '(wlan.da==40:c3:36:07:d4:bf || '
                                                               'wlan.da==ff:ff:ff:ff:ff:ff) &&!'
                                                               '(wlan.fc.type==0) && tcp')
        return pkt_list
    except IOError:
        print('IOError: File could not be accessed.')


def extract_packet_data_pyshark(filtered_packets):
    """

    :param filtered_packets:
    :return: dbm_antsignal, datarate, duration, seq, ttl
    """
    # Initialise empty lists for packet features
    dbm_antsignal = []  # Received Signal Strength Indication RSSI
    datarate = []
    duration = []
    seq = []
    ttl = []

    # start_features = time.time()
    # Extract all data from packets into lists.
    # This loop is the bottleneck, investigate ways to speed it up. 11.6 seconds to process the normal pcap file
    for pkt in filtered_packets:
        dbm_antsignal.append(int(pkt.radiotap.dbm_antsignal))
        datarate.append(int(pkt.radiotap.datarate))
        duration.append(int(pkt.wlan.duration))
        seq.append(int(pkt.wlan.seq))
        ttl.append(int(pkt.ip.ttl))
    # end_feature = time.time()
    # print(end_feature-start_features)

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
    stats = PacketStatistics()

    # Extract the first 30 packets (or x amount set by user)
    # Store in new arrays
    # Take and store averages for each new array
    # Take next packet
    # Compare new packet with averages
    # Add or disregard new package

    # Extract the first 'sw_size' amount of packets and store in new arrays
    # sw -> sliding window + 'feature name'
    sw_dbm_antsignal = dbm_antsignal[0:30]
    sw_datarate = datarate[0:30]
    sw_duration = duration[0:30]
    sw_seq = seq[0:30]
    sw_ttl = ttl[0:30]

    array_dict = {'sw_dbm_antsignal':sw_dbm_antsignal, 'sw_datarate':sw_datarate,
                  'sw_duration':sw_duration, 'sw_seq':sw_seq, 'sw_ttl':sw_ttl }
    ave_dict = {}

    # loop over each array and calculate the mean for each array storing it in new dictionary
    for k, v in array_dict.items():
        ave_dict[k] = mean(v)


def initialise_feature_arrays(dbm_antsignal, datarate, duration, seq, ttl, sw_size):
    # Take next packet
    # Compare new packet with averages
    # Add or disregard new package

    # Extract the first 'sw_size' amount of packets and store in new arrays
    # sw -> sliding window + '_feature_name'
    sw_dbm_antsignal = dbm_antsignal[0:sw_size]
    sw_datarate = datarate[0:sw_size]
    sw_duration = duration[0:sw_size]
    sw_seq = seq[0:sw_size]
    sw_ttl = ttl[0:sw_size]

    array_dict = {'dbm_antsignal': dbm_antsignal, 'datarate': datarate,
                  'duration': duration, 'seq': seq, 'ttl': ttl}

    sw_dict = {'sw_dbm_antsignal': sw_dbm_antsignal, 'sw_datarate': sw_datarate,
               'sw_duration': sw_duration, 'sw_seq': sw_seq, 'sw_ttl': sw_ttl}
    ave_dict = {}

    # loop over each array and calculate the mean for each array storing it in new dictionary
    for k, v in sw_dict.items():
        ave_dict[k] = mean(v)

    return array_dict, ave_dict, sw_dict
    # print(ave_dict)


def packet_analysis(array_dict, ave_dict, sw_dict, sw_size):

    # Loop through the arrays, extract the next packets one at a time
    # compare features with average values and then add or disregard packet
    # and then update averages
    start = sw_size + 1
    print('length of dbm_antsignal array {}'.format(len(dbm_antsignal)))
    stop = len(dbm_antsignal)
    step = 1
    counter = 0

    for x in range(start, stop, step):
        for k_1, arrays in array_dict.items():
            for k_2, ave in ave_dict.items():
                # counter += 1
                # returns the absolute distance between the average for the feature and the new packet feature
                distance(ave, arrays[x])
    # print(counter)


#  def analyse_packets(array_dict, ave_dict):


# Maybe put these three functions inside their own class called PacketAnalysis()?
def mean(data):
    return statistics.mean(data)


def mode(data):
    return statistics.mode(data)


def distance(ave, new_val):
    return abs(ave - new_val)


# Possibly change Statistics to PacketAnalysis, PacketStats ?
class PacketStatistics():
    ave_length = 0
    # Not sure what needs to go in __init__ yet? Probably not mean and mode? Mean and mode need to be calculated
    # and then fed in as reference values for the new packets to be compared to. Maybe separate class for mean and mode
    # calculations and separate class for comparing new packet values to the mean and mode reference values.

    # def __init__(self, rssi_mean, rate_mean, duration_mean, seq_mean, ttl_mean):
    #     # Some of these will become mode rather than mean
    #     # These are all instance variables?
    #     self._rssi_mean = rssi_mean
    #     self._rate_mean = rate_mean
    #     self._duration_mean = duration_mean
    #     self._seq_mean = seq_mean
    #     self._ttl_mean = ttl_mean

    # @staticmethod  # will remove the 'static' warning
    def mean(self, data):  # This is an instance method?
        """
        Returns the mean of the numbers
        :param data
        :return:
        """
        self.is_not_used()  # removes the 'static' warning from PyCharm
        data = data[0:self.ave_length]  # Step 1 - extracts 30 data values

        return mean(data)

    def mode(self, data):
        """
        Returns the mode of the numbers
        :param nums:
        :return:
        """
        self.is_not_used()  # removes the 'static' warning from PyCharm
        data = data[0:self.ave_length]

        return mode(data)

    def diff_from_ave(self, ref_val):
        """

        :param ref_val:
        :return:
        """

    def is_not_used(self):
        pass


# class SlidingWindow(PacketStatistics):
#     def __int__(self):
#         PacketStatistics.__init__(self)
#
#     def compare_values(self):
#
#     def extract_data(self):


if __name__ == "__main__":
    """
    Five metrics will be analysed to give evidence of an attack. The metrics identified are: Received Signal Strength 
    Indication (RSSI), Transmission (or injection) Rate, Frame Sequence number, Duration field (or Network Allocation
    Vector, NAV) and Time To Live (TTL). 
    
    In this program these metrics have the following variable names -->
    
    1. dbm_Antsignal
    2. datarate
    3. Seq
    4. duration
    5. ttl
    """

    # Default settings
    input_file = '/pcap_files/variable_rate_normal_mon_VP'
    output_file = 'data.csv'
    sw_val = 30

    # Initialise cmd line argument parser
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--input_file",
                    help="the pcap file to load (include path if not in wd)")
    ap.add_argument("-a", "--output_file",
                    help="specify file to save packet data too")
    ap.add_argument("-o", "--online", action='store_true',
                    help="initiate online packet sniffing")
    ap.add_argument("-s", "--sliding_window",
                    help="the number of packets to include in sliding window, (e.g. 10, 30, 50, 100)")

    # read arguments from the command line
    args = ap.parse_args()

    # set up cmd line variables for use in script
    # check to make sure online mode and read from file haven't both been set

    # if args.online and args.input_file:
    #     raise IndexError('Must provide either --input_file or --online with command line not both,'
    #                      'use --help for further info.')

    # elif args.input_file and not args.online:
    #     pcap_file = args.input_file
    #     if not os.path.exists(pcap_file):
    #         raise FileNotFoundError('No such file or directory exists.')

    #elif not args.online and not args.input_file:
        #print('Please select either online packet sniffing or load packets from pcap. '
              #'Use --help for further info.')
    #else:
       # print('Can only specify either online packet sniffing or load packets from file, not both. '
              #'Use --help for further info')

    if args.output_file:
        data_file = args.output_file

    # ensure sliding window value is an integer
    if args.sliding_window:
        sw_val = args.sliding_window
        # print(sw_val)
        # print(isinstance(sw_val, int))
        if not isinstance(sw_val, int):
            raise ValueError('Sliding window value must be an integer, (e.g. 10, 30, 50, 100)')

    if args.input_file:
        input_file_FLAG = True
    else:
        input_file_FLAG = False

    # begin either online sniffing or loading from pcap file
    try:
        if args.online is True and input_file_FLAG is False:
            live_capture()

        elif input_file_FLAG is True and args.online is False:
            pcap_file = args.input_file

            if os.path.exists(pcap_file) is False:
                raise FileNotFoundError()

            print('About to start filtering packets...\n')
            #  Call function to filter all packets.
            #  pkt_list = filter_packets_scapy(pcap_file_num)
            pkt_list = filter_packets_pyshark(pcap_file)

            print('All packets filtered. \n'
                  'Data is now being extracted from packets... \n')

            # Call function to extract relevant data from packets.
            # extract_packet_data_scapy(pkt_list)

            dbm_antsignal, datarate, duration, seq, ttl = extract_packet_data_pyshark(pkt_list)

            array_dict, ave_dict, sw_dict = initialise_feature_arrays(dbm_antsignal, datarate, duration, seq, ttl, sw_val)

            packet_analysis(array_dict, ave_dict, sw_dict, sw_val)

        elif args.online is True and input_file_FLAG is True:
            raise IndexError()
        else:
            print('Invalid flags set on cmd line, use --help for further info')

    except FileNotFoundError:
        print('FileNotFoundError: file or directory does not exist.')
    #except IndexError:
     #   print('IndexError: must provide either --input_file or --online, not both,'
      #        'use --help for further info.')
    finally:
        print('Exiting program!')
        # sys.exit(1)
   # # Allow user to decide whether to sniff in real time or load a pcap file
    # while 1:
    #     print('1. Sniff packets online \n'
    #           '2. Load pcap file ')
    #
    #     sniff_option = int(input('Select packet sniffing option: '))
    #
    #     if sniff_option == 1:
    #         # Sniff packets in real time
    #         live_capture()
    #         break
    #
    #     elif sniff_option == 2:
    #
    #         # Lookup dict for different pcap files
    #         pcap_dict = {'1': 'variable_rate_normal_mon_VP',
    #                      '2': 'variable_rate_attack01_mon_VP',
    #                      '3': 'variable_rate_attack02_mon_VP',
    #                      '4': 'variable_rate_inthemix_mon_VP'}
    #
    #         # Menu of options for which pcap file to process
    #         print('1. variable_rate_normal_mon_VP \n'
    #               '2. variabel_rate_attack01_mon_VP \n'
    #               '3. variable_rate_attack02_mon_VP \n'
    #               '4. variable_rate_inthemix_mon_VP')
    #
    #         pcap_file_num = str(input('Enter pcap file no. to use: '))
    #
    #         # Call function to filter all packets.
    #         # pkt_list = filter_packets_scapy(pcap_file_num)
    #         pkt_list = filter_packets_pyshark(pcap_file_num)
    #
    #         print('All packets filtered. \n'
    #               'Data is now being extracted from packets. \n')
    #
    #         # Call function to extract relevant data from packets.
    #         # extract_packet_data_scapy(pkt_list)
    #         dbm_antsignal, datarate, duration, seq, ttl = extract_packet_data_pyshark(pkt_list)
    #
    #         initialise_feature_arrays(dbm_antsignal, datarate, duration, seq, ttl)
    #
    #
    #         break
    #
    #     else:
    #         print('Please enter either 1 or 2 from keyboard.')
