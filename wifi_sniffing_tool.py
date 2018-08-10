import pyshark, argparse, statistics, itertools, os, time
import numpy as np
import traceback
from scapy.all import *
from autobpa import AutoBPA
from packetstatistics import PacketStatistics
from select_metrics import SelectMetrics


# potentially add all the pyshark functions into a class, filter, extract and live capture?
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

    # Extract all data from packets into lists.
    # This loop is the bottleneck, investigate ways to speed it up. 11.6 seconds to process the normal pcap file
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





if __name__ == "__main__":
    """
    Five metrics will be collated to give evidence of an attack. The metrics identified are: Received Signal Strength 
    Indication (RSSI), Transmission (or injection) Rate, Frame Sequence number, Duration field (or Network Allocation
    Vector, NAV) and Time To Live (TTL). 
    
    In this program these metrics have the following variable names -->
    
    RSSI --> dbm_Antsignal
    Rate --> datarate
    Seq -- > Seq
    NAV --> duration
    TTL --> ttl
    """

    # Default settings
    input_file = '/pcap_files/variable_rate_normal_mon_VP'
    output_file = 'data.csv'
    sw_val = 30
    select_metrics = 31

    # Initialise cmd line argument parser and flags
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--input_file",
                    help="the pcap file to load (include path if not in wd)")
    ap.add_argument("-a", "--output_file",
                    help="specify file to save packet data too")
    ap.add_argument("-o", "--online", action='store_true',
                    help="initiate online packet sniffing")
    ap.add_argument("-s", "--sliding_window",
                    help="the number of packets to include in sliding window, (e.g. 10, 30, 50, 100)")
    ap.add_argument("-b", "--features", type=int,
                    help="integer to select which metrics should be used. See \"select_metrics.txt\" for further info.")

    # read arguments from the command line
    args = ap.parse_args()

    # ensure sliding window value is an integer
    if args.sliding_window:
        sw_val = args.sliding_window
        # print(sw_val)
        # print(isinstance(sw_val, int))
        if not isinstance(sw_val, int):
            raise ValueError('Sliding window value must be an integer, (e.g. 10, 30, 50, 100)')

    # assign cmd line arguments to program variables
    if args.output_file:
        data_file = args.output_file
    if args.input_file:
        input_file_FLAG = True
    else:
        input_file_FLAG = False
    if args.features:
        select_metrics = args.features

    # begin either online sniffing or loading from pcap file
    try:
        metric_1 = SelectMetrics(metric_val=select_metrics)

        if metric_1.validate() is False:
            raise ValueError

        # if 1 <= select_metrics <= 31:
        #     result = metric_combination(select_metrics)
        # else:
        #     raise ValueError

        if args.online is True and input_file_FLAG is False:
            live_capture()

        elif input_file_FLAG is True and args.online is False:
            pcap_file = args.input_file

            if os.path.exists(pcap_file) is False:
                raise FileNotFoundError()

            print('About to start filtering packets...\n')
            #  Call function to filter all packets.
            pkt_list = filter_packets_pyshark(pcap_file)

            print('All packets filtered. \n'
                  'Data is now being extracted from packets... \n')

            # Call function to extract relevant data from packets.
            dbm_antsignal, datarate, duration, seq, ttl = extract_packet_data_pyshark(pkt_list)

            array_dict, ave_dict, sw_dict = initialise_feature_arrays(dbm_antsignal, datarate,
                                                                      duration, seq, ttl, sw_val)

            packet_analysis(array_dict, ave_dict, sw_dict, sw_val)
            print('Program finished without error.\n')

        elif args.online is True and input_file_FLAG is True:
            raise IndexError()
        else:
            print('Unknown error. Check cmd line flags, use --help for further info or select_metrics.txt')

    except FileNotFoundError:
        print('FileNotFoundError: file or directory does not exist.')
    except ValueError:
        print('ValueError: --features must be an integer between 1 and 31, see "select_metrics.txt" for help.')
    except:
        print(traceback.format_exc())

    finally:
        print('Exiting program!')
