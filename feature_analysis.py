from autobpa import AutoBPA

from select_metrics import SelectMetrics
from ds import DempsterShafer
from pyds.pyds import MassFunction
import numpy as np
from packet_analysis import PacketAnalysis
from autobpa import AutoBPA


def metric_analysis(dbm_antsignal, datarate, duration, seq, ttl, sw_size, metric_val):
    # Extract the first 'sw_size' amount of packets and store in new arrays
    # sw -> sliding window + '_feature_name'
    sw_dbm_antsignal = dbm_antsignal[0:sw_size]
    sw_datarate = datarate[0:sw_size]
    sw_duration = duration[0:sw_size]
    sw_seq = seq[0:sw_size]
    sw_ttl = ttl[0:sw_size]

    array_dict = {'RSSI': dbm_antsignal, 'Rate': datarate,
                  'NAV': duration, 'Seq': seq, 'TTL': ttl}

    sw_dict = {'RSSI': sw_dbm_antsignal, 'Rate': sw_datarate,
               'NAV': sw_duration, 'Seq': sw_seq, 'TTL': sw_ttl}

    metric = SelectMetrics(metric_val=metric_val)
    features_to_analyse = metric.metric_combination()

    instance_dict = {}
    attack_count = 0
    # create an instance of each feature that is going to be analysed
    # and store the instances in a dictionary 'instance_dict'
    for feature in features_to_analyse:
        for key, arrays in sw_dict.items():
            if feature == key:
                name = feature + '_bpa'
                print('Creating instance of AutoBPA class called {}. '
                      'The Feature is : {}'.format(name, feature))

                # creates an instance of AutoBPA class
                x = globals()[name] = AutoBPA(data=arrays, sw=sw_size)
                instance_dict[key] = x

    print(instance_dict)

    start, stop, step = sw_size + 1, len(dbm_antsignal), 1
    count = 0
    # consider trying to multithread/multiprocess this secion, or use itertools to speed up the process.
    # potentially use itertools.product and dict.keys(), dict.values(), dict.items() to loop through them all
    ds = DempsterShafer()
    for incr in range(start, stop, step):
        # potentially replace the following 2 for loops and if statement with zip function. As long as array_dict
        # and instance_dict have the same arrays in them in the same order it should work fine.
        # potentially use itertools.compress to remove redundant arrays, i.e. metrics, that we are not going to process

        MF_list = []
        print('Packet number {}'.format(count))
        for array, inst in zip(array_dict.items(), instance_dict.items()):
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
            if not len(MF_list) == (len(features_to_analyse) - 1):
                MF_list.append(m)

        # Combine all the mass functions into one result for N, A, U
        result = ds.fuse_metrics(m, MF_list)

        # find the maximum out of N, A, U for the combined DS values
        bpa_result = max(result.keys(), key=(lambda key: result[key]))

        # consider moving this next section into a series of callable functions.
        # this will allow the elif 'u' statement to be handled by the current
        # functions for N and A.
        if 'n' in bpa_result:
            # This code will increment the sliding window arrays
            for norm_arrays, sw_arrays in zip(array_dict.values(), sw_dict.items()):
                # print(sw_dict[sw_arrays[0]])
                sw_dict[sw_arrays[0]] = sliding_window(norm_arrays, sw_size, count)
                # print(sw_dict[sw_arrays[0]])
        elif 'a' in bpa_result:
            # This code will print to users screen. 'Attack detected in packet no .#.
            # Closing web browser down

            # This should delete the packets that have been detected as attacks
            # from the arrays ensuring that when the sw_arrays are incremented
            # they will not include 'bad' values in them that could skew the stats.
            attack_count += 1
            print('ATTACK detected in packet {}. Closing web browser!'.format(count))
            for metric, array in array_dict.items():
                # check the count value includes the sw_size and is incremented in the correct place
                array_dict[metric] = np.delete(array, count)

        elif 'u' in bpa_result:
            # This code will determine whether N, A is bigger and use that as the metric
            # to process.

            # bpa_result just returns the single maximum therefore the following
            # code will not work, it will have to be if 'n' in result > .... etc
            # not ... in bpa_result

            # if 'n' in bpa_result >= 'a' in bpa_result:
            #     for norm_arrays, sw_arrays in zip(array_dict.values(), sw_dict.items()):
            #         # print(sw_dict[sw_arrays[0]])
            #         sw_dict[sw_arrays[0]] = sliding_window(norm_arrays, sw_size, count)
            #         # print(sw_dict[sw_arrays[0]])
            # else:
            #     print('ATTACK detected in packet {}. Closing web browser!'.format(count))
            #     for metric, array in array_dict.items():
            #         # check the count value includes the sw_size and is incremented in the correct place
            #         array_dict[metric] = np.delete(array, count)
            pass
        else:
            print('PASS')
            # In the unlikely case that there is no maximum value some code here can determine
            # what action should be taken
            # pass

        count += 1
        #if count == 2000:
        print(attack_count)
         #   break

        # break   # create instance of DS for each metric with the BPA value dictionary
            # m = MassFunction(ds_dict)
            # print(m)
            # append all metrics to list except the last one
            # if not len(ds_list) == (len(features_to_analyse) - 1):
                # ds_list.append(m)

            # name = k_2 + '_dict'

            # x = globals()[name] = AutoBPA(data=arrays, sw=sw_size)
            # instance_dict[key] = x
            # if count == 0:
            #     print('{} \n'
            #           'Normal = {} \n'
            #           'Attack = {} \n'
            #           'Uncert. = {} \n'
            #           'phi = {} \n'.format(k_2, n, a, u, phi))
            #     break

            # count += 1


        #print(count)
        # Must use zip function above other wise m.combine_disjunctive will fail when k_1 !== k_2
        # print(ds_list)
        # Combine all the mass functions into one result for N, A, U
        # result = m.combine_disjunctive(ds_list)
        # ds.process_ds(result)


def sliding_window(metric_array, window_size, start_value):

    # for x in range(start_value, stop=(len(metric_array)-window_size), step=1):

    return metric_array[start_value:(start_value+window_size)]


def oo_function(metric_dict, select_metrics, sw_val, ds_timer):
    ds_inst = DempsterShafer
    inst_bpa = AutoBPA

    slt_metrics = SelectMetrics(metric_val=select_metrics)

    features_to_analyse = slt_metrics.metric_combination()
    #
    # produce initial sliding windows frame in dict called sw_dict
    sw_dict = {}
    for metric, metric_array in zip(features_to_analyse, metric_dict.values()):
        sw_dict[metric] = metric_array[0:sw_val]

    # print(sw_dict)

    # create dynamic instances of AutoBPA class
    instance_dict = inst_bpa.create_instance(features_to_analyse,
                                             sw_dict, sw_val)

    pa = PacketAnalysis(array_dict=metric_dict, sw_dict=sw_dict,
                        sw_val=sw_val, features_to_analyse=features_to_analyse,
                        ds_timer=ds_timer)

    pa.process_packets()

    # pkt_count += 1
