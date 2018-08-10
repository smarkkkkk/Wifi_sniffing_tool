import itertools


class SelectMetrics:

    def __init__(self, metric_val=31):
        self._metric_val = metric_val

    # Function will validate the inputted metric value
    def validate(self):
        if 1 <= self._metric_val <= 31:
            return True
        else:
            return False

    def metric_combination(self):
        numbers = [1, 2, 4, 8, 16]

        # this will return the combination of numbers that sum to select_metrics integer
        result = [seq for i in range(len(numbers), 0, -1) for seq in itertools.combinations(numbers, i)
                  if sum(seq) == self._metric_val]

        metric_dict = {'RSSI': 1, 'Rate': 2, 'NAV': 4, 'Seq': 8, 'TTL': 16}

        # determine which metrics are going to be analysed based on the metric integer provided by user
        metrics = [k for k, v in metric_dict.items() if v in result[0]]

        return metrics
