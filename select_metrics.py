import itertools


class SelectMetrics:
    """
    This class determines if the integer entered by the user is valid and what metrics will be
    processed based on the ineteger.
    """

    def __init__(self, metric_val):
        self._metric_val = metric_val

    # Function will validate the inputted metric value
    def validate(self):
        """
        This function validates the metric integer by ensuring it is between 1 and 31 and not a float

        :return: True/False: returns a bool based on the result of validating the integer
        """

        if 1 <= self._metric_val <= 31:
            return True
        else:
            return False

    def metric_combination(self):
        """
        This function determines what metrics are going to be analysed based on the integer that was
        entered

        :return: metrics: list of strings of each metric to be analysed.
        """
        numbers = [1, 2, 4, 8, 16]

        # this will return the combination of numbers that sum to select_metrics integer
        result = [seq for i in range(len(numbers), 0, -1) for seq in itertools.combinations(numbers, i)
                  if sum(seq) == self._metric_val]

        metric_dict = {'RSSI': 1, 'Rate': 2, 'NAV': 4, 'Seq': 8, 'TTL': 16}

        # determine which metrics are going to be analysed based on the metric integer provided by user
        metrics = [k for k, v in metric_dict.items() if v in result[0]]

        return metrics
