import csv
import numpy as np


class PacketAnalysis:
    def __init(self, **kwargs):


    def list_to_array(self, lists):
        lists = [lists]

        for _list in lists:

    def data_to_csv(self):
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

    def sliding_window(self, array, sw_val, incr_val):
        sw_dbm_antsignal = dbm_antsignal[0:sw_size]
        sw_datarate = datarate[0:sw_size]
        sw_duration = duration[0:sw_size]
        sw_seq = seq[0:sw_size]
        sw_ttl = ttl[0:sw_size]

