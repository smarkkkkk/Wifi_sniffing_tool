import time
import numpy as np
from ds import DempsterShafer
from pyds.pyds import MassFunction
from autobpa import AutoBPA


class PacketAnalysis:
    """
    This class does the main processinf of the packets for offline mode. It uses the filtered packets
    and uses instances of PacketStatistics and AutoBPA to produce statistics on the metric data
    which is used to calculate the BPA. The metric BPAs are then fused using Dempster Shafer to produce
    final result which determines either sliding window or delete frame data.
    """

    def __init__(self, array_dict, sw_dict, sw_val, features_to_analyse, **kwargs):
        self._array_dict = array_dict
        self._sw_dict = sw_dict
        self._sw_val = sw_val
        self._features_to_analyse = features_to_analyse
        if 'ds_timer' in kwargs: self._ds_timer = kwargs['ds_timer']

    def process_packets(self):
        """
        This function loops through every packet, calculates the statistics for the metrics, produces BPA
        values then fuses BPAs for each metric into a final result. It then decides whether to initiate
        the sliding window or delete the frame data.

        :param:
        :return:
        """
        ds = DempsterShafer()
        inst_bpa = AutoBPA
        # print(inst_bpa)

        # create dynamic instances of AutoBPA class
        instance_dict, ttl_array = inst_bpa.create_instance(self._features_to_analyse,
                                                            self._sw_dict, self._sw_val)
        # function variables
        start, stop, step = self._sw_val + 1, len(self._array_dict['RSSI']), 1
        pkt_count = 0
        attack_count = 0
        incr = self._sw_val
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
            print('Packet number {}'.format(pkt_count))
            # print('sw_dict inside packet processing: {}'.format(self._sw_dict))
            # print('\n\n')
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
                # print('ds_dict for metric {}: {}'.format(inst[0], ds_dict))
                # create instance of MF for each metric with the BPA value dictionary
                m = MassFunction(ds_dict)

                # append all metrics to list except the last one
                if not len(MF_list) == (len(self._features_to_analyse) - 1):
                    MF_list.append(m)
            # print(data_list)

            # Combine all the mass functions into one result for N, A, U
            # If ds_time flag is set then also calculate the time it takes to fuse metrics
            if self._ds_timer is True:
                start = time.time()
                result = ds.fuse_metrics(m, MF_list)
                ds_calc_time = time.time() - start
                print(ds_calc_time)
            else:
                result = ds.fuse_metrics(m, MF_list)

            # find the maximum out of N, A, U for the combined DS values
            bpa_result = max(result.keys(), key=(lambda key: result[key]))
            # print(bpa_result)
            if 'n' in bpa_result:
                # print('Reached n')
                # print(self._sw_dict)
                # print('self._sw_dict before sliding_window function: {}'.format(self._sw_dict))
                # print('\n\n')
                self.sliding_window(incr)
                # print('self._sw_dict after sliding_window function: {}'.format(self._sw_dict))
                # print('\n\n')
                instance_dict, ttl_array = inst_bpa.create_instance(self._features_to_analyse,
                                                                    self._sw_dict, self._sw_val)
                # print('self._sw_dict after new AutoBPA instances created function: {}'.format(self._sw_dict))
                # print('\n\n')
                # print(instance_dict)
                # print(self._sw_dict)
                # print(np.setdiff1d(self._sw_dict['TTL'], ttl_array))
                pkt_count += 1
                incr += 1
            elif 'a' in bpa_result:
                attack_count += 1
                print('ATTACK detected in packet {}. Closing web browser!'.format(pkt_count))
                # print('Data that needs to be deleted: {}'.format(data_list))
                # print(self._array_dict['RSSI'][(incr - 5):(incr + 5)])
                self.delete_frame_data(incr)
                pkt_count += 1
                # print(self._array_dict['RSSI'][(incr-5):(incr+5)])
            elif 'u' in bpa_result:
                pass
            else:
                print('Reached else and pass')
                pass

            # if pkt_count == 700:
            #     break

            # print('\n\n')
            # incr += 1
            # pkt_count += 1
            #print('Incr value is: {}, '
                  #'pkt_count value is: {}'.format(incr, pkt_count))
        print('Number of malicious frames detected: {} '.format(attack_count))
        # print(inst_bpa)

    def sliding_window(self, incr):
        """
        This function moves the current metric windows along one place when the frame has been
        identified as Normal. If the current frame is at the end of the pcap file then the window
        cannot be moved along.

        :param incr: current frame increment value. Actually begins at the length of sliding window, not 0
        :return:
        """
        # for x in range(start_value, stop=(len(metric_array)-window_size), step=1):
        # print(start_value + self._sw_val)
        # print(len((self._array_dict['RSSI'])))
        start_val = incr - self._sw_val
        end_val = incr
        if end_val < len((self._array_dict['RSSI'])):
            for norm_arrays, sw_arrays in zip(self._array_dict.values(), self._sw_dict.items()):
                # print(start_value, (start_value+self._sw_val))
                # print(self._sw_dict[sw_arrays[0]])
                self._sw_dict[sw_arrays[0]] = norm_arrays[start_val:incr]
                # print(self._sw_dict[sw_arrays[0]])
        else:
            print('Sliding window can no longer be implemented due to end of frames approaching!')
        # return self._sw_dict

    def delete_frame_data(self, count):
        """
        This function deletes the current frame if it has been identified to be malicious, i.e. Attack.
        :param count: frame that needs to be deleted
        :return:
        """
        # print('ATTACK detected in packet {}. Closing web browser!'.format(count))
        for metric, array in self._array_dict.items():
            print('Deleting data: {}'.format(self._array_dict[metric][count]))
            # print(self._array_dict[metric][(count - 5):(count + 5)])
            # check the count value includes the sw_size and is incremented in the correct place
            self._array_dict[metric] = np.delete(array, count)
            # print(self._array_dict[metric][(count-5):(count+5)])
        # return self._array_dict

    def debug_file(self):
        """
        This function will produce the debug file. It will write all necessary data to a file to enable
        debugging of the performance of the program.

        :return:
        """
        # Current frame no.
        # Current frame metric data
        # Current sliding window data
        # Distances for each metric
        # DS probabilities, BPA's, time to calculate
        # Fusion results for each metric
        # Averages for each metric
        # Final result for frame
        # Current number of malicious frames detected

