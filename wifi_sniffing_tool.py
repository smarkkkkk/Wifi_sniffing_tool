"""
Author: Jim Matthews
Contact email: j.matthews-14@student.lboro.ac.uk
Supervisor: Dr Kostas Kyriakopoulos, Signal Processing and Networks Research Group, Loughborough University
Group URL: http://www.lboro.ac.uk/departments/meme/research/research-groups/signal-processing-networks/
Date: 4th September 2018
This work was carried out as part of a Wolfson School of Mechanical, Electrical and Manufacturing
Engineering funded summary bursary.
"""

import argparse
from scapy.all import *
from select_metrics import SelectMetrics
import feature_analysis
from pyshark_tools import PysharkTools


def main():
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

    Dempster Shafer will be applied on the metrics to produce a belief in Normal, Attack, and Uncertainty
    If the frame is malicious, i.e. Attack, the web browser is shut down. If the frame is Normal then the frame data is
    added to the sliding window that produces the 'normal' network behaviour.
    """
    # Default settings
    input_file = '/pcap_files/variable_rate_normal_mon_VP'
    output_file = 'data.csv'
    sw_val = 30
    select_metrics = 31
    capture_filter = '(wlan.sa==00:25:9c:cf:8a:73 || ' \
                     'wlan.sa==00:25:9c:cf:8a:71) &&' \
                     '(wlan.da==40:c3:36:07:d4:bf || ' \
                     'wlan.da==ff:ff:ff:ff:ff:ff) ' \
                     '&&!(wlan.fc.type==0)&&tcp'

    interface = 'mon0'

    # Initialise cmd line argument parser and flags
    ap = argparse.ArgumentParser()
    ap.add_argument("-r", "--input_file",
                    help="the pcap file to load (include path if not in wd)")
    ap.add_argument("-a", "--output_file",
                    help="specify file to save packet data too")
    ap.add_argument("-w", "--sliding_window",
                    help="the number of packets to include in sliding window, (e.g. 10, 30, 50, 100)")
    ap.add_argument("-s", "--features", type=int,
                    help="integer to select which metrics should be used. See \"select_metrics.txt\" for further info.")
    ap.add_argument("-f", "--capture_filter",
                    help="capture filter to apply to packets")
    ap.add_argument("-i", "--interface",
                    help="interface to sniff on")

    ap.add_argument("-t", "--ds_time", action="store_true",
                    help="calculate time for DS (Dempster Shafer) algorithm to compute")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="run program in quiet mode")
    ap.add_argument("-d", "--debug_file", action="store_true",
                    help="print debug info in txt file")
    ap.add_argument("-o", "--online", action='store_true',
                    help="initiate online packet sniffing")

    # read arguments from the command line
    args = ap.parse_args()

    # ensure sliding window value is an integer
    if args.sliding_window:
        sw_val = int(args.sliding_window)

    # assign cmd line arguments to program variables
    if args.output_file:
        data_file = args.output_file
    if args.input_file:
        input_file_FLAG = True
    else:
        input_file_FLAG = False
    if args.features:
        select_metrics = args.features
    if args.ds_time:
        ds_timer = args.ds_time
    else:
        ds_timer = False
    # begin either online sniffing or loading from pcap file
    try:
        metric_1 = SelectMetrics(metric_val=select_metrics)
        py_shark = PysharkTools()

        if metric_1.validate() is False:
            print('Select metrics value, {}, is incorrect.'
                  'Ensure the value is between 1 and 31 and an integer.'.format(select_metrics))

        if args.online is True and input_file_FLAG is False:
            py_shark.live_capture()

        elif input_file_FLAG is True and args.online is False:
            pcap_file = args.input_file

            if os.path.exists(pcap_file) is False:
                raise FileNotFoundError()

            if args.quiet is False:
                print('About to start filtering packets...\n')
            #  Call function to filter all packets.
            pkt_list = py_shark.filter_packets(pcap_file)

            if args.quiet is False:
                print('All packets filtered. \n'
                      'Data is now being extracted from packets... \n')

            # Call function to extract relevant data from packets.
            dbm_antsignal, datarate, duration, seq, ttl, metric_dict = py_shark.extract_data(pkt_list)

            # when extract_data is updated the new PacketAnalysis class will
            # only need metric_dict to work correctly
            # metric_dict = py_shark.extract_data(pkt_list)
            # calls function to process packets, calc. DS and
            # fuse metrics producing N, A, U for each frame
            feature_analysis.oo_function(metric_dict, select_metrics, sw_val, ds_timer)

            # feature_analysis.metric_analysis(dbm_antsignal, datarate, duration, seq, ttl, sw_val, select_metrics)

            # array_dict, ave_dict, sw_dict = initialise_feature_arrays(dbm_antsignal, datarate,
            #                                                           duration, seq, ttl, sw_val)
            #
            # packet_analysis(array_dict, ave_dict, sw_dict, sw_val)
            if args.quiet is False:
                print('Program finished without error.\n')

        elif args.online is True and input_file_FLAG is True:
            raise IndexError()
        else:
            print('Unknown error. Check cmd line flags, use --help for further info or select_metrics.txt')

    except FileNotFoundError:
        print('FileNotFoundError: file or directory does not exist.')
    # except ValueError:
    # print('ValueError: --features must be an integer between 1 and 31, see "select_metrics.txt" for help.')
    except:
        print(traceback.format_exc())

    finally:
        if args.quiet is False:
            print('Exiting program!')


if __name__ == "__main__":
    main()

