import csv
import numpy as np
from ds import DempsterShafer
from pyds.pyds import MassFunction
from autobpa import AutoBPA


class PacketAnalysis:

    def __init__(self, array_dict, sw_dict, sw_val, features_to_analyse, **kwargs):
        self._array_dict = array_dict
        self._sw_dict = sw_dict
        self._sw_val = sw_val
        self._features_to_analyse = features_to_analyse

    def process_packets(self):
        ds = DempsterShafer()
        inst_bpa = AutoBPA
        print(inst_bpa)

        # create dyanmic instances of AutoBPA class
        instance_dict = inst_bpa.create_instance(self._features_to_analyse,
                                                 self._sw_dict, self._sw_val)
        # function variables
        start, stop, step = self._sw_val + 1, len(self._array_dict['RSSI']), 1
        pkt_count = 0
        attack_count = 0
        incr = 0
        print(len(self._array_dict['RSSI']))
        # consider trying to multithread/multiprocess this secion, or use itertools to speed up the process.
        # potentially use itertools.product and dict.keys(), dict.values(), dict.items() to loop through them all
        # for incr in range(start, stop, step):
        while incr < len(self._array_dict['RSSI']):
            # potentially replace the following 2 for loops and if statement with zip function. As long as array_dict
            # and instance_dict have the same arrays in them in the same order it should work fine.
            # potentially use itertools.compress to remove redundant arrays, i.e. metrics, that we are
            # not going to process
            data_list = []
            MF_list = []
            # print('Packet number {}'.format(pkt_count))
            print('sw_dict inside packet processing: {}'.format(self._sw_dict))
            print('\n\n')
            for array, inst in zip(self._array_dict.items(), instance_dict.items()):

                data_list.append(array[1][incr])

                # print('Metric: {}, value: {}'.format(inst[0],array[1][incr]))
                mean = instance_dict[inst[0]].mean()
                instance_dict[inst[0]].distance(array[1][incr])
                instance_dict[inst[0]].box_plot()
                # print('Metric: {}, mean: {}'.format(inst[0], mean))
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
                # print(self._sw_dict)
                print('self._sw_dict before sliding_window function: {}'.format(self._sw_dict))
                print('\n\n')
                self.sliding_window(incr)
                print('self._sw_dict after sliding_window function: {}'.format(self._sw_dict))
                print('\n\n')
                instance_dict = inst_bpa.create_instance(self._features_to_analyse,
                                                         self._sw_dict, self._sw_val)
                print('self._sw_dict after new AutoBPA instances created function: {}'.format(self._sw_dict))
                print('\n\n')
                # print(instance_dict)
                # print(self._sw_dict)
                pkt_count += 1
                incr += 1
            elif 'a' in bpa_result:
                attack_count += 1
                print('ATTACK detected in packet {}. Closing web browser!'.format(pkt_count))
                # print('Data that needs to be deleted: {}'.format(data_list))
                self.delete_frame_data(incr)
                pkt_count += 1
            elif 'u' in bpa_result:
                pass
            else:
                pass
            # incr += 1
            # pkt_count += 1
            #print('Incr value is: {}, '
                  #'pkt_count value is: {}'.format(incr, pkt_count))
        print(attack_count)
        # print(inst_bpa)

    def sliding_window(self, start_value):
        # for x in range(start_value, stop=(len(metric_array)-window_size), step=1):
        # print(start_value + self._sw_val)
        # print(len((self._array_dict['RSSI'])))
        if (start_value + self._sw_val) < len((self._array_dict['RSSI'])):
            for norm_arrays, sw_arrays in zip(self._array_dict.values(), self._sw_dict.items()):
                # print(start_value, (start_value+self._sw_val))
                # print(self._sw_dict[sw_arrays[0]])
                self._sw_dict[sw_arrays[0]] = norm_arrays[start_value:(start_value + self._sw_val)]
                # print(self._sw_dict[sw_arrays[0]])
        else:
            print('Sliding window can no longer be implemented due to end of frames approaching!')
        # return self._sw_dict

    def delete_frame_data(self, count):
        # print('ATTACK detected in packet {}. Closing web browser!'.format(count))
        for metric, array in self._array_dict.items():
            # print('Deleting data: {}'.format(self._array_dict[metric][count]))
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





# import csv
# import numpy as np
# from ds import DempsterShafer
# from pyds.pyds import MassFunction
# from autobpa import AutoBPA
#
#
# class PacketAnalysis:
#
#     def __init__(self, array_dict, sw_dict, sw_val, features_to_analyse, instance_dict, pkt_count, attack_count):
#         self._array_dict = array_dict
#         self._sw_dict = sw_dict
#         self._sw_val = sw_val
#         self._features_to_analyse  = features_to_analyse
#         self._instance_dict = instance_dict
#         self._pkt_count = pkt_count
#         self._attack_count = attack_count
#
#     def process_packets(self, ds_inst, inst_bpa, incr):
#         # ds = DempsterShafer()
#         # inst_bpa = AutoBPA
#         #
#         # # create dynamic instances of AutoBPA class
#         # instance_dict = inst_bpa.create_instance(self._features_to_analyse,
#         #                                          self._sw_dict, self._sw_val)
#         # # function variables
#         # start, stop, step = self._sw_val, len(self._array_dict['RSSI']), 1
#         # pkt_count = 0
#         # attack_count = 0
#         #
#         # print('The first 0->29 packets are used '
#         #       'to develop the normal network behaviour.')
#         # # consider trying to multithread/multiprocess this secion, or use itertools to speed up the process.
#         # # potentially use itertools.product and dict.keys(), dict.values(), dict.items() to loop through them all
#         # for incr in range(start, stop, step):
#         # potentially replace the following 2 for loops and if statement with zip function. As long as array_dict
#         # and instance_dict have the same arrays in them in the same order it should work fine.
#         # potentially use itertools.compress to remove redundant arrays, i.e. metrics, that we are
#         # not going to process
#
#         # MF_list = []
#         # print('Packet number {}'.format(pkt_count))
#         # ds = DempsterShafer
#         MF_list = []
#         for array, inst in zip(self._array_dict.items(), self._instance_dict.items()):
#             # print('Metric: {}, value: {}'.format(inst[0],array[1][incr]))
#
#             # data_val = array[1][incr]
#             #     inst_auto_bpa = instance_dict[inst[0]]
#             self._instance_dict[inst[0]].mean()
#             self._instance_dict[inst[0]].distance(array[1][incr])
#             self._instance_dict[inst[0]].box_plot()
#
#             # N, A, U (BPA) are returned in a dictionary
#             # that can be inputted into MF class
#             ds_dict = self._instance_dict[inst[0]].combined_value(value=array[1][incr])
#
#             # create instance of MF for each metric with the BPA value dictionary
#             m = MassFunction(ds_dict)
#
#             # append all metrics to list except the last one
#             if not len(MF_list) == (len(self._features_to_analyse) - 1):
#                 MF_list.append(m)
#         #print(MF_list)
#         print(m)
#         # Combine all the mass functions into one result for N, A, U
#         result = ds_inst.fuse_metrics(m_last=m, mf_list=MF_list)
#
#         # find the maximum out of N, A, U for the combined DS values
#         bpa_result = max(result.keys(), key=(lambda key: result[key]))
#
#         if 'n' in bpa_result:
#             self.sliding_window(self._pkt_count)
#             self._instance_dict = inst_bpa.create_instance(self._features_to_analyse,
#                                                            self._sw_dict, self._sw_val)
#         elif 'a' in bpa_result:
#             self._attack_count += 1
#             print('ATTACK detected in packet {}. Closing web browser!'.format(self._pkt_count))
#             self.delete_frame_data(incr)
#         # elif 'u' in bpa_result:
#         #     continue
#         # else:
#         #     continue
#
#         self._pkt_count += 1
#
#         print(self._attack_count)
#
#     def sliding_window(self, start_value):
#         # start_value = start_value + 30
#         # for x in range(start_value, stop=(len(metric_array)-window_size), step=1):
#         for norm_arrays, sw_arrays in zip(self._array_dict.values(), self._sw_dict.items()):
#             self._sw_dict[sw_arrays[0]] = norm_arrays[start_value:(start_value + self._sw_val)]
#
#         # return self._sw_dict
#
#     def delete_frame_data(self, count):
#         print('ATTACK detected in packet {}. Closing web browser!'.format(count))
#         for metric, array in self._array_dict.items():
#             # check the count value includes the sw_size and is incremented in the correct place
#             self._array_dict[metric] = np.delete(array, count)
#
#         # return self._array_dict
#
#     # def list_to_array(self, lists):
#     #     lists = [lists]
#     #
#     #     for _list in lists:
#     #
#     # def data_to_csv(self):
#     #     # Convert all packet feature lists to numpy arrays
#     #     dbm_antsignal = np.asarray(dbm_antsignal)
#     #     datarate = np.asarray(datarate)
#     #     duration = np.asarray(duration)
#     #     seq = np.asarray(seq)
#     #     ttl = np.asarray(ttl)
#     #
#     #     # Write all packet feature data to .csv file
#     #     pkt_incr = 0
#     #     pkt_data = np.zeros((len(dbm_antsignal), 5))
#     #
#     #     while pkt_incr < len(dbm_antsignal):
#     #         pkt_data[pkt_incr][0] = dbm_antsignal[pkt_incr]
#     #         pkt_data[pkt_incr][1] = datarate[pkt_incr]
#     #         pkt_data[pkt_incr][2] = duration[pkt_incr]
#     #         pkt_data[pkt_incr][3] = seq[pkt_incr]
#     #         pkt_data[pkt_incr][4] = ttl[pkt_incr]
#     #         # print(dbm_antsignal[pkt_incr], datarate[pkt_incr], duration[pkt_incr], seq[pkt_incr], ttl[pkt_incr])
#     #         pkt_incr += 1
#     #
#     #     np.savetxt('data.csv', pkt_data, fmt='%1.10e', delimiter='\t')
#     #
#     # def sliding_window(self, array, sw_val, incr_val):
#     #     sw_dbm_antsignal = dbm_antsignal[0:sw_size]
#     #     sw_datarate = datarate[0:sw_size]
#     #     sw_duration = duration[0:sw_size]
#     #     sw_seq = seq[0:sw_size]
#     #     sw_ttl = ttl[0:sw_size]

