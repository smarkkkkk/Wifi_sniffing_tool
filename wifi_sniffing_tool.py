import pyshark, argparse, statistics, itertools, os, time
import numpy as np
import traceback
from scapy.all import *
from autobpa import AutoBPA
from packetstatistics import PacketStatistics
from select_metrics import SelectMetrics
import feature_analysis


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

            feature_analysis.metric_analysis(dbm_antsignal, datarate, duration, seq, ttl, sw_val)

            # array_dict, ave_dict, sw_dict = initialise_feature_arrays(dbm_antsignal, datarate,
            #                                                           duration, seq, ttl, sw_val)
            #
            # packet_analysis(array_dict, ave_dict, sw_dict, sw_val)
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
