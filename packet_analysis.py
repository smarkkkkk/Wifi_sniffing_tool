import csv
import numpy as np
from ds import DempsterShafer
from pyds.pyds import MassFunction
from autobpa import AutoBPA


class PacketAnalysis:

    def __init__(self, array_dict, sw_dict, sw_val, features_to_analyse):
        self._array_dict = array_dict
        self._sw_dict = sw_dict
        self._sw_val = sw_val
        self._features_to_analyse  = features_to_analyse

    def process_packets(self):
        ds = DempsterShafer()
        inst_bpa = AutoBPA

        # create dynamic instances of AutoBPA class
        instance_dict = inst_bpa.create_instance(self._features_to_analyse,
                                                 self._sw_dict, self._sw_val)
        # function variables
        start, stop, step = self._sw_val + 1, len(self._array_dict['RSSI']), 1
        pkt_count = 0
        attack_count = 0

        # consider trying to multithread/multiprocess this secion, or use itertools to speed up the process.
        # potentially use itertools.product and dict.keys(), dict.values(), dict.items() to loop through them all
        for incr in range(start, stop, step):
            # potentially replace the following 2 for loops and if statement with zip function. As long as array_dict
            # and instance_dict have the same arrays in them in the same order it should work fine.
            # potentially use itertools.compress to remove redundant arrays, i.e. metrics, that we are
            # not going to process

            MF_list = []
            print('Packet number {}'.format(pkt_count))
            for array, inst in zip(self._array_dict.items(), instance_dict.items()):
                # print('Metric: {}, value: {}'.format(inst[0],array[1][incr]))
                instance_dict[inst[0]].mean()
                instance_dict[inst[0]].distance(array[1][incr])
                instance_dict[inst[0]].box_plot()

                # N, A, U (BPA) are returned in a dictionary
                # that can be inputted into MF class
                ds_dict = instance_dict[inst[0]].combined_value(value=array[1][incr])

                # create instance of MF for each metric with the BPA value dictionary
                m = MassFunction(ds_dict)

                # append all metrics to list except the last one
                if not len(MF_list) == (len(self._features_to_analyse) - 1):
                    MF_list.append(m)

            # Combine all the mass functions into one result for N, A, U
            result = ds.fuse_metrics(m, MF_list)

            # find the maximum out of N, A, U for the combined DS values
            bpa_result = max(result.keys(), key=(lambda key: result[key]))

            if 'n' in bpa_result:
                self.sliding_window(pkt_count)
                instance_dict = inst_bpa.create_instance(self._features_to_analyse,
                                                         self._sw_dict, self._sw_val)
            elif 'a' in bpa_result:
                attack_count += 1
                print('ATTACK detected in packet {}. Closing web browser!'.format(pkt_count))
                self.delete_frame_data(pkt_count)
            elif 'u' in bpa_result:
                pass
            else:
                pass

    def sliding_window(self, start_value):
        # for x in range(start_value, stop=(len(metric_array)-window_size), step=1):
        for norm_arrays, sw_arrays in zip(self._array_dict.values(), self._sw_dict.items()):
            self._sw_dict[sw_arrays[0]] = norm_arrays[start_value:(start_value + self._sw_val)]

        # return self._sw_dict

    def delete_frame_data(self, count):
        print('ATTACK detected in packet {}. Closing web browser!'.format(count))
        for metric, array in self._array_dict.items():
            # check the count value includes the sw_size and is incremented in the correct place
            self._array_dict[metric] = np.delete(array, count)

        # return self._array_dict

    # def list_to_array(self, lists):
    #     lists = [lists]
    #
    #     for _list in lists:
    #
    # def data_to_csv(self):
    #     # Convert all packet feature lists to numpy arrays
    #     dbm_antsignal = np.asarray(dbm_antsignal)
    #     datarate = np.asarray(datarate)
    #     duration = np.asarray(duration)
    #     seq = np.asarray(seq)
    #     ttl = np.asarray(ttl)
    #
    #     # Write all packet feature data to .csv file
    #     pkt_incr = 0
    #     pkt_data = np.zeros((len(dbm_antsignal), 5))
    #
    #     while pkt_incr < len(dbm_antsignal):
    #         pkt_data[pkt_incr][0] = dbm_antsignal[pkt_incr]
    #         pkt_data[pkt_incr][1] = datarate[pkt_incr]
    #         pkt_data[pkt_incr][2] = duration[pkt_incr]
    #         pkt_data[pkt_incr][3] = seq[pkt_incr]
    #         pkt_data[pkt_incr][4] = ttl[pkt_incr]
    #         # print(dbm_antsignal[pkt_incr], datarate[pkt_incr], duration[pkt_incr], seq[pkt_incr], ttl[pkt_incr])
    #         pkt_incr += 1
    #
    #     np.savetxt('data.csv', pkt_data, fmt='%1.10e', delimiter='\t')
    #
    # def sliding_window(self, array, sw_val, incr_val):
    #     sw_dbm_antsignal = dbm_antsignal[0:sw_size]
    #     sw_datarate = datarate[0:sw_size]
    #     sw_duration = duration[0:sw_size]
    #     sw_seq = seq[0:sw_size]
    #     sw_ttl = ttl[0:sw_size]

