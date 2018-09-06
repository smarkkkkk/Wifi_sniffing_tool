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
import os


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
    pcap_file = '/pcap_files/variable_rate_normal_mon_VP'
    output_file = 'data.csv'
    sw_val = 30
    select_metrics = 31
    display_filter = '(wlan.sa==00:25:9c:cf:8a:73 ||'  \
                     'wlan.sa==00:25:9c:cf:8a:71) &&'  \
                     '(wlan.da==40:c3:36:07:d4:bf ||'  \
                     'wlan.da==ff:ff:ff:ff:ff:ff) '    \
                     '&&!(wlan.fc.type==0)&&tcp'

    # display_filter = '!(wlan.fc.type==0)&&tcp'

    mon_interface = 'mon0'

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
    ap.add_argument("-x", "--suppress_warnings", action="store_true",
                    help="calculating BPAs for some frames will trigger RuntimeWarnings due to dividing by zero, "
                         "set this flag to suppress those particular warnings.")

    # read arguments from the command line
    args = ap.parse_args()

    # assign cmd line arguments to program variables
    if args.sliding_window:
        sw_val = int(args.sliding_window)
    # if args.output_file:
    #     data_file = args.output_file
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
    if args.capture_filter:
        display_filter = str(args.capture_filter)
    if args.interface:
        mon_interface = str(args.interface)
    if args.input_file:
        pcap_file = args.input_file

    debug_file_FLAG = args.debug_file
    quiet = args.quiet
    warning_flag = args.suppress_warnings

    # begin either online sniffing or loading from pcap file
    try:
        metric_1 = SelectMetrics(metric_val=select_metrics)
        py_shark = PysharkTools()

        if warning_flag is True:
            import warnings
            warnings.filterwarnings(action='ignore', category=RuntimeWarning, module="autobpa")

        # ensures that any previous debug file is removed before new data is appended to it.
        if debug_file_FLAG is True:
            if os.path.exists('debug.txt'):
                os.remove('debug.txt')

        if metric_1.validate() is False:
            print('Select metrics value, {}, is incorrect.'
                  'Ensure the value is between 1 and 31 and an integer.'.format(select_metrics))

        if args.online is True and input_file_FLAG is False:
            if quiet is False:
                print('Starting Live Capture')
            py_shark.live_capture(mon_interface, display_filter)

        elif input_file_FLAG is True and args.online is False:
            if os.path.exists(pcap_file) is False:
                raise FileNotFoundError()

            if quiet is False:
                print('Offline mode enabled\n')
                print('Input file: [{}]\n'
                      'Sliding window size: [{}]\n'
                      'Capture filter: [\'{}\']\n'
                      'Features integer: [{}]\n'
                      'DS timing: [{}]\n'
                      'Debug file: [{}]\n'
                      'Runtime Warning suppression: [{}]'.format(pcap_file, sw_val, display_filter,
                                                                 select_metrics, ds_timer, debug_file_FLAG,
                                                                 warning_flag))
                print('About to start filtering packets.\n')

            #  Call function to filter all packets.
            pkt_list = py_shark.filter_packets(pcap_file, display_filter)

            if quiet is False:
                print('All packets filtered. \n'
                      'Data is now being extracted from packets... \n')

            # Call function to extract relevant data from packets.
            dbm_antsignal, datarate, duration, seq, ttl, metric_dict = py_shark.extract_data(pkt_list)

            # main packet processing function. See function definitions for more details
            feature_analysis.oo_function(metric_dict, select_metrics, sw_val, ds_timer,
                                         quiet, debug_file_FLAG)

            if quiet is False:
                print('Program finished without error.\n')

        elif args.online is True and input_file_FLAG is True:
            raise IndexError()
        else:
            print('Check cmd line flags, online and offline sniffing cannot be done at the same time.'
                  'Use --help for further info or select_metrics.txt')

    except FileNotFoundError:
        print('FileNotFoundError: file or directory does not exist.')
    except:
        print(traceback.format_exc())
    finally:
        if quiet is False:
            print('Exiting program!')


if __name__ == "__main__":
    main()
