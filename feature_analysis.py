from select_metrics import SelectMetrics
from packet_analysis import PacketAnalysis


def oo_function(metric_dict, select_metrics, sw_val, ds_timer, quiet):
    # ds_inst = DempsterShafer
    # inst_bpa = AutoBPA

    slt_metrics = SelectMetrics(metric_val=select_metrics)

    features_to_analyse = slt_metrics.metric_combination()
    #
    # produce initial sliding windows frame in dict called sw_dict
    sw_dict = {}
    for metric, metric_array in zip(features_to_analyse, metric_dict.values()):
        sw_dict[metric] = metric_array[0:sw_val]

    # print(sw_dict)

    # create dynamic instances of AutoBPA class
    # instance_dict = inst_bpa.create_instance(features_to_analyse,
    #                                          sw_dict, sw_val)

    pa = PacketAnalysis(array_dict=metric_dict, sw_dict=sw_dict,
                        sw_val=sw_val, features_to_analyse=features_to_analyse,
                        ds_timer=ds_timer, quiet_flag=quiet)

    pa.process_packets()

    # pkt_count += 1
