import statistics
import numpy as np


# PacketStatistics needs the sw_val for the box plot function.
# Pass in as initialising variable like local binary patterns function for project
class PacketStatistics:
    # may need to set __init__ up as **kwargs to ensure that the median,
    # and quartile values are not required
    # when initiating the class

    def __init__(self, sw, median, lower_quart, upper_quart, inter_quart_range):
        self._sw = sw
        self._median = median
        self._lower_quart = lower_quart
        self._upper_quart = upper_quart
        self._inter_quart = inter_quart_range

    @staticmethod
    def mean(data):
        return statistics.mean(data)

    @staticmethod
    def frequency(data):
        return statistics.mode(data)

    def median(self, data):
        self._median = statistics.median(data)

    @staticmethod
    def distance(ave, new_val):
        return abs(ave - new_val)

    def box_plot(self, data):
        # produces the quartiles and median, stores them in self.variable_name
        # autoBPA will inherit from the statistics class and therefore will have access to
        # the quartile values through the self.__init__ inheritance thing. AutoBPA will use the current packet and
        # self. variables to determine the probability assignment.

        sorted_data = np.sort(data)
        self._lower_quart = sorted_data[int((self._sw + 1) / 4)]
        self._upper_quart = sorted_data[int(3 * ((self._sw + 1) / 4))]
        self._inter_quart = int(self._upper_quart - self._lower_quart)
