import feature_analysis
import csv
import numpy as np

csv_file = csv.reader(open('../data/data.csv','r'))
csv_array = []

for line in csv_file:
    line = ''.join(line)
    csv_array.append(line.split('\t'))

csv_array = [[float(x) for x in row] for row in csv_array]
csv_array = np.array(csv_array)


metric_dict = {}
metric_name = {1: 'RSSI', 2: 'Rate', 4: 'NAV', 8: 'Seq', 16: 'TTL'}
metric_sequence = {1: 0, 2: 1, 4: 2, 8: 3, 16: 4}

chosenMetric = [1, 2, 4, 8]

for k, v in metric_name.items():
    if k in chosenMetric:
        metric_dict[metric_name[k]] = csv_array[:, metric_sequence[k]]
print(sum(chosenMetric[0:4]))
feature_analysis.oo_function(metric_dict, sum(chosenMetric[0:4]), 30, False, False, True)

