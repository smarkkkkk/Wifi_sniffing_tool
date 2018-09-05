import pyshark
import numpy as np


class PysharkTools:
    """
    This class contains all PyShark functionality necessary for this program to run.
    """
    # def __init__(self, **kwargs):
    #     if 'filename' in kwargs: self._pcap_fn = kwargs['filename']
    # if 'mean' in kwargs: self._mean = kwargs['mean']

    @staticmethod
    def filter_packets(pcap_fn, disp_filter):
        """
        This function filters the packets inside the pcap file. The filter to be applied is in 'Wireshark'
        format and can be set from the cmd line argument.

        :param pcap_fn: pcap filename
        :param disp_filter: filter to be applied
        :return: pkt_list: list of filtered packets
        """
        pkt_list = pyshark.FileCapture(pcap_fn, display_filter=disp_filter)
        return pkt_list

    @staticmethod
    def extract_data(filtered_packets):
        """
        This function will extract the features from each of the packets. In this case we are extracting
        RSSI, Rate, NAV, Seq and TTL into numpy arrays. All of the data is saved in a csv file for debugging
        and future use.

        :param filtered_packets:
        :return: dbm_antsignal, datarate, duration, seq, ttl, metric_dict
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
            dbm_antsignal.append(float(pkt.radiotap.dbm_antsignal))
            datarate.append(float(pkt.radiotap.datarate))
            duration.append(float(pkt.wlan.duration))
            seq.append(float(pkt.wlan.seq))
            ttl.append(float(pkt.ip.ttl))

        # Convert all packet feature lists to numpy arrays
        dbm_antsignal = np.asarray(dbm_antsignal)
        datarate = np.asarray(datarate)
        duration = np.asarray(duration)
        seq = np.asarray(seq)
        ttl = np.asarray(ttl)

        # Write all packet feature data to .csv file
        pkt_incr = 0
        pkt_data = np.zeros((len(dbm_antsignal), 5))

        # while pkt_incr < len(dbm_antsignal):
        #     pkt_data[pkt_incr][0] = dbm_antsignal[pkt_incr]
        #     pkt_data[pkt_incr][1] = datarate[pkt_incr]
        #     pkt_data[pkt_incr][2] = duration[pkt_incr]
        #     pkt_data[pkt_incr][3] = seq[pkt_incr]
        #     pkt_data[pkt_incr][4] = ttl[pkt_incr]
        #     # print(dbm_antsignal[pkt_incr], datarate[pkt_incr], duration[pkt_incr], seq[pkt_incr], ttl[pkt_incr])
        #     pkt_incr += 1
        #
        # np.savetxt('data.csv', pkt_data, fmt='%1.10e', delimiter='\t')
        #
        # metric_dict = {'RSSI': dbm_antsignal, 'Rate': datarate,
        #                'NAV': duration, 'Seq': seq, 'TTL': ttl}

        # RSSI, Rate, TTL, NAV, sequence number (MAC Layer - Not TCP seq number),
        # and finally inter arrival time. I attach the txt file for attack02
        pkt_data_kostas = np.zeros((len(dbm_antsignal), 5))

        while pkt_incr < len(dbm_antsignal):
            pkt_data_kostas[pkt_incr][0] = dbm_antsignal[pkt_incr]
            pkt_data_kostas[pkt_incr][1] = datarate[pkt_incr]
            pkt_data_kostas[pkt_incr][2] = ttl[pkt_incr]
            pkt_data_kostas[pkt_incr][3] = duration[pkt_incr]
            pkt_data_kostas[pkt_incr][4] = seq[pkt_incr]

            # print(dbm_antsignal[pkt_incr], datarate[pkt_incr], duration[pkt_incr], seq[pkt_incr], ttl[pkt_incr])
            pkt_incr += 1
        np.savetxt('normal.txt', pkt_data_kostas,  delimiter='\t')

        return dbm_antsignal, datarate, duration, seq, ttl#, metric_dict

    @staticmethod
    def live_capture(mon_interface, disp_filter):
        """
        This function is for online use of the program. It uses PyShark to continuously sniff packets on the
        interface set and applying a filter as specified from the cmd line. It will then process the packet
        data with DS and detect attacks.
        :return:
        """
        # may need to change interface string depending on what monitor mode interface appears from airmon-ng command
        capture = pyshark.LiveCapture(interface=mon_interface, display_filter=disp_filter)
        # for pkt in capture.sniff(packet_count=0):
        #     print(pkt.radiotap.dbm_antsignal, pkt.radiotap.datarate, pkt.wlan.duration, pkt.wlan.seq, pkt.ip.ttl)
        for pkt in capture.sniff_continuously(packet_count=0):
            print(pkt.radiotap.dbm_antsignal, pkt.radiotap.datarate, pkt.wlan.duration, pkt.wlan.seq, pkt.ip.ttl)
