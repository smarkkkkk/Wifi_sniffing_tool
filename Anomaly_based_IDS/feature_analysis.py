from select_metrics import SelectMetrics
from packet_analysis import PacketAnalysis


def oo_function(metric_dict, select_metrics, sw_val, ds_timer, quiet, debug_file):

    slt_metrics = SelectMetrics(metric_val=select_metrics)

    features_to_analyse = slt_metrics.metric_combination()
    # print(features_to_analyse)
    # produce initial sliding windows frame in dict called sw_dict
    sw_dict = {}

    # Here exists a bug (fxk)
    # for metric, metric_array in zip(features_to_analyse, metric_dict.values()):
    #     sw_dict[metric] = metric_array[0:sw_val]
    for metric in features_to_analyse:
        sw_dict[metric] = metric_dict[metric][0:sw_val]

    pa = PacketAnalysis(array_dict=metric_dict, sw_dict=sw_dict,
                        sw_val=sw_val, features_to_analyse=features_to_analyse,
                        ds_timer=ds_timer, quiet_flag=quiet, debug_file=debug_file)

    pa.process_packets()
