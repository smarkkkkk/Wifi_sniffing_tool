import time
import numpy as np
from ds import DempsterShafer
from pyds.pyds import MassFunction
from autobpa import AutoBPA
import pickle
import json


class PacketAnalysis:
    """
    This class does the main processinf of the packets for offline mode. It uses the filtered packets
    and uses instances of PacketStatistics and AutoBPA to produce statistics on the metric data
    which is used to calculate the BPA. The metric BPAs are then fused using Dempster Shafer to produce
    final result which determines either sliding window or delete frame data.
    """

    def __init__(self, array_dict, sw_dict, sw_val, features_to_analyse, quiet_flag, ds_timer):
        self._array_dict = array_dict
        self._sw_dict = sw_dict
        self._sw_val = sw_val
        self._features_to_analyse = features_to_analyse
        self._quiet = quiet_flag
        self._ds_timer = ds_timer

    def process_packets(self):
        """
        This function loops through every packet, calculates the statistics for the metrics, produces BPA
        values then fuses BPAs for each metric into a final result. It then decides whether to initiate
        the sliding window or delete the frame data.

        :param:
        :return:
        """
        # class instances
        ds = DempsterShafer()
        inst_bpa = AutoBPA

        # create dynamic instances of AutoBPA class
        instance_dict = inst_bpa.create_instance(self._features_to_analyse,
                                                            self._sw_dict, self._sw_val)
        # function variables
        pkt_count = 0
        attack_count = 0
        incr = self._sw_val

        # consider trying to multithread/multiprocess this secion, or use itertools to speed up the process.
        # potentially use itertools.product and dict.keys(), dict.values(), dict.items() to loop through them all
        while incr < len(self._array_dict['RSSI']):
            # potentially replace the following 2 for loops and if statement with zip function. As long as array_dict
            # and instance_dict have the same arrays in them in the same order it should work fine.
            # potentially use itertools.compress to remove redundant arrays, i.e. metrics, that we are
            # not going to process
            data_list = []
            MF_list = []
            # print('Packet number {}'.format(pkt_count))

            for array, inst in zip(self._array_dict.items(), instance_dict.items()):

                data_list.append(array[1][incr])

                mean = instance_dict[inst[0]].mean()
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
            # If ds_time flag is set then also calculate the time it takes to fuse metrics
            if self._ds_timer is True:
                start = time.time()
                result = ds.fuse_metrics(m, MF_list)
                ds_calc_time = time.time() - start

            else:
                result = ds.fuse_metrics(m, MF_list)

            # find the maximum out of N, A, U for the combined DS values
            bpa_result = max(result.keys(), key=(lambda key: result[key]))

            if 'n' in bpa_result:

                self.sliding_window(incr)
                instance_dict = inst_bpa.create_instance(self._features_to_analyse,
                                                         self._sw_dict, self._sw_val)
                pkt_count += 1
                incr += 1

            elif 'a' in bpa_result:
                if self._quiet is False:
                    print('ATTACK detected in packet {}. Closing web browser!'.format(pkt_count))
                self.delete_frame_data(incr)
                pkt_count += 1
                attack_count += 1

            elif 'u' in bpa_result:
                pass
            else:
                pass

            self.debug_file(pkt_count, attack_count, data_list)

        if self._quiet is False:
            print('\nNumber of malicious frames detected: {} '.format(attack_count))

    def sliding_window(self, incr):
        """
        This function moves the current metric windows along one place when the frame has been
        identified as Normal. If the current frame is at the end of the pcap file then the window
        cannot be moved along.

        :param incr: current frame increment value. Actually begins at the length of sliding window, not 0
        :return:
        """

        start_val = incr - self._sw_val
        end_val = incr

        if end_val < len((self._array_dict['RSSI'])):
            for norm_arrays, sw_arrays in zip(self._array_dict.values(), self._sw_dict.items()):
                self._sw_dict[sw_arrays[0]] = norm_arrays[start_val:incr]

        else:
            if self._quiet is False:
                print('Sliding window can no longer be implemented due to end of frames approaching!')

    def delete_frame_data(self, count):
        """
        This function deletes the current frame if it has been identified to be malicious, i.e. Attack.
        :param count: frame that needs to be deleted
        :return:
        """

        for metric, array in self._array_dict.items():
            self._array_dict[metric] = np.delete(array, count)

    def debug_file(self, pkt_count, attack_count, data_list):
        """
        This function will produce the debug file. It will write all necessary data to a file to enable
        debugging of the performance of the program.

        :return:
        """
        # Current frame no. //
        # Current frame metric data  //
        # Current sliding window data
        # Distances for each metric
        # DS probabilities, BPA's, time to calculate
        # Fusion results for each metric
        # Averages for each metric
        # Final result for frame
        # Current number of malicious frames detected
        metric_list = ['RSSI', 'Rate', 'NAV', 'Seq', 'TTL']

        with open('debug.txt', 'a') as debug_file:
            debug_file.write('Frame number: %d\n' % pkt_count)
            debug_file.write('Current frame data.')
            # debug_file.write('\n')
            debug_file.writelines('%s : %d ' % (metric, value) for metric, value in zip(self._features_to_analyse,
                                                                                             data_list))
            debug_file.write('Current sliding window data: \n')
            # col_format = '{:<5}'*len(self._sw_dict) + '\n'
            # for metric, sw_value in zip(self._features_to_analyse, self._sw_dict.values()):
            for k, v in self._sw_dict.items():
                if v == self._features_to_analyse[-1]:
                    debug_file.write('{}: {} \n'.format(str(k), str(v)))
                else:
                    debug_file.write('{}: {}'.format(str(k), str(v)))


            # for x in zip(self._sw_dict.values()):
            #     debug_file.write(col_format.format(str(*x)))

            # for arrays in self._sw_dict.values():
            #     data =
            # for metric in metric_list:
            #     debug_file.write(metric)
            #     debug_file.writelines(self._sw_dict[metric])
            # debug_file.write(json.dumps(self._sw_dict))
            debug_file.write('NUmber of malicious frames detected: %d \n' % attack_count)

        debug_file.close()
