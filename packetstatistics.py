import statistics
import numpy as np


class PacketStatistics:
    """
    This class contains functions that apply some statistical method on data, such as: mean, mode, median,
    euclidean distance and box plot. It is also the parent class of AutoBPA.
    """

    def __init__(self, data, **kwargs):
        self._data = data
        if 'mean' in kwargs: self._mean = kwargs['mean']
        if 'dist_mean' in kwargs: self._dist_mean = kwargs['dist_mean']
        if 'dist_maxval' in kwargs: self._dist_maxval = kwargs['dist_maxval']

        if 'sw' in kwargs: self._sw = kwargs['sw']
        if 'median' in kwargs: self._median = kwargs['median']
        if 'lower_quart' in kwargs: self._lower_quart = kwargs['lower_quart']
        if 'upper_quart' in kwargs: self._upper_quart = kwargs['upper_quart']
        if 'inter_quart_range' in kwargs: self._inter_quart_range = kwargs['inter_quart_range']

    def mean(self):
        """
        This function calculates the mean of a data set.
        :return: self._mean
        """
        self._mean = statistics.mean(self._data)

        return self._mean

    def frequency(self):
        """
        This function calculates the mode of a data set.
        :return: mode
        """
        return statistics.mode(self._data)

    def median(self):
        """
        This function calculates the median of a data set.
        :return:
        """
        self._median = statistics.median(self._data)

    def distance(self, new_val):
        """
        This function calculates the euclidean distance from a defined reference of normality, in this case
        the mean to the current data point and the max of the data.

        :param new_val: current value being analysed
        :return:
        """
        if abs(min(self._data) - self._mean) >= abs(self._mean - max(self._data)):
            self._dist_maxval = abs(min(self._data) - self._mean)
            # print('smaller')
        else:
            self._dist_maxval = abs(max(self._data) - self._mean)

        self._dist_mean = abs(self._mean - new_val)

    def box_plot(self):
        """
        This function calculates the box plot quartiles of the data set, i.e. lower quartile (LQ),
        upper quartile (UQ) and inter-quartile range (IQR)

        :return:
        """

        sorted_data = np.sort(self._data)
        self._lower_quart = sorted_data[int((self._sw + 1) / 4)]
        self._upper_quart = sorted_data[int(3 * ((self._sw + 1) / 4))]
        self._inter_quart_range = int(self._upper_quart - self._lower_quart)

