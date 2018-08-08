from autobpa import AutoBPA
from packetstatistics import PacketStatistics


# def metric_analysis():
# def feature_statistics(dbm_antsignal, datarate, duration, seq, ttl):

# conside changing to metric analysis

def metric_analysis(dbm_antsignal, datarate, duration, seq, ttl, sw_size):
    # Extract the first 'sw_size' amount of packets and store in new arrays
    # sw -> sliding window + '_feature_name'
    sw_dbm_antsignal = dbm_antsignal[0:sw_size]
    sw_datarate = datarate[0:sw_size]
    sw_duration = duration[0:sw_size]
    sw_seq = seq[0:sw_size]
    sw_ttl = ttl[0:sw_size]

    array_dict = {'dbm_antsignal': dbm_antsignal, 'datarate': datarate,
                  'duration': duration, 'seq': seq, 'ttl': ttl}

    sw_dict = {'sw_dbm_antsignal': sw_dbm_antsignal, 'sw_datarate': sw_datarate,
               'sw_duration': sw_duration, 'sw_seq': sw_seq, 'sw_ttl': sw_ttl}
    ave_dict = {}

    stats_1 = PacketStatistics
    # loop over each array and calculate the mean/frequency for each array storing it in new dictionary
    for k, v in sw_dict.items():
        if k == 'sw_ttl':
            ave_dict[k] = stats_1.frequency(v)
        else:
            ave_dict[k] = stats_1.mean(v)

    stats_2 = PacketStatistics

    # Loop through the arrays, extract the next packets one at a time
    # compare features with average values and then add or disregard packet
    # and then update averages
    print('lenght of dbm_antsignla is {}'.format(len(dbm_antsignal)))
    start, stop, step = sw_size + 1, len(dbm_antsignal), 1

    counter = 0

    for x in range(start, stop, step):
        for k_1, arrays in array_dict.items():
            for k_2, ave in ave_dict.items():
                # counter += 1
                # returns the absolute distance between the average for the feature and the new packet feature
                stats_2.distance(ave, arrays[x])
    # print(counter)


def initialise_feature_arrays(dbm_antsignal, datarate, duration, seq, ttl, sw_size):
    """
    """
    # Extract the first 'sw_size' amount of packets and store in new arrays
    # sw -> sliding window + '_feature_name'
    sw_dbm_antsignal = dbm_antsignal[0:sw_size]
    sw_datarate = datarate[0:sw_size]
    sw_duration = duration[0:sw_size]
    sw_seq = seq[0:sw_size]
    sw_ttl = ttl[0:sw_size]

    array_dict = {'dbm_antsignal': dbm_antsignal, 'datarate': datarate,
                  'duration': duration, 'seq': seq, 'ttl': ttl}

    sw_dict = {'sw_dbm_antsignal': sw_dbm_antsignal, 'sw_datarate': sw_datarate,
               'sw_duration': sw_duration, 'sw_seq': sw_seq, 'sw_ttl': sw_ttl}
    ave_dict = {}

    stats_1 = PacketStatistics
    # loop over each array and calculate the mean/frequency for each array storing it in new dictionary
    for k, v in sw_dict.items():
        if k == 'sw_ttl':
            ave_dict[k] = stats_1.frequency(v)
        else:
            ave_dict[k] = stats_1.mean(v)

    return array_dict, ave_dict, sw_dict

def packet_analysis(array_dict, ave_dict, sw_dict, sw_size):
    stats_2 = PacketStatistics
    # Loop through the arrays, extract the next packets one at a time
    # compare features with average values and then add or disregard packet
    # and then update averages
    start, stop, step = sw_size + 1, len(dbm_antsignal), 1
    counter = 0

    for x in range(start, stop, step):
        for k_1, arrays in array_dict.items():
            for k_2, ave in ave_dict.items():
                # counter += 1
                # returns the absolute distance between the average for the feature and the new packet feature
                stats_2.distance(ave, arrays[x])
    # print(counter)
