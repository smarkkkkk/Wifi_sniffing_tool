import statistics
import numpy as np


# PacketStatistics needs the sw_val for the box plot function.
# Pass in as initialising variable like local binary patterns function for project
class PacketStatistics:
    # may need to set __init__ up as **kwargs to ensure that the median,
    # and quartile values are not required
    # when initiating the class

    # def __init__(self, sw, median, lower_quart, upper_quart, inter_quart_range):
    def __init__(self, data, **kwargs):
        # These are object variables, they aren't initialised until after the object is defined.
        # Use kwargs so they don't have to be initialised in the correct order.
        # Set to default to 0 if they aren't set in the class instance?
        self._data = data
        if 'mean' in kwargs: self._mean = kwargs['mean']
        if 'dist_mean' in kwargs: self._dist_mean = kwargs['dist_mean']
        if 'dist_maxval' in kwargs: self._dist_maxval = kwargs['dist_maxval']

        if 'sw' in kwargs: self._sw = kwargs['sw']
        if 'median' in kwargs: self._median = kwargs['median']
        if 'lower_quart' in kwargs: self._lower_quart = kwargs['lower_quart']
        if 'upper_quart' in kwargs: self._upper_quart = kwargs['upper_quart']
        if 'inter_quart_range' in kwargs: self._inter_quart_range = kwargs['inter_quart_range']

    # These functions are called methods in Python classes
    def mean(self):
        self._mean = statistics.mean(self._data)
        # print('Mean value is: {}'.format(self._mean))
        return self._mean

    # Frequency is mode in this program
    def frequency(self):
        return statistics.mode(self._data)

    def median(self):
        self._median = statistics.median(self._data)

    def distance(self, new_val):

        if abs(min(self._data) - self._mean) >= abs(self._mean - max(self._data)):
            self._dist_maxval = abs(min(self._data) - self._mean)
            # print('smaller')
        else:
            self._dist_maxval = abs(max(self._data) - self._mean)

        self._dist_mean = abs(self._mean - new_val)

        # Uncommenting this section assigns 0.01 to a lot of metric processing
        # BPA values. This then gives A = 0.5, which is too
        # high to be justified given the conditions.

        # if self._dist_maxval == 0:
        #     self._dist_maxval = 0.01
        # if self._dist_mean == 0:
        #     self._dist_mean = 0.01

        # print('Dist_mean is: {}. Dist_maxval is : {}'.format(self._dist_mean, self._dist_maxval))

    def box_plot(self):
        # produces the quartiles and stores them in self.variable_name
        # autoBPA will inherit from the statistics class and therefore will have access to
        # the quartile values through the self.__init__ inheritance thing. AutoBPA will use
        # the current packet and self. variables to determine the probability assignment.

        sorted_data = np.sort(self._data)
        # print('sorted data is: {}'.format(sorted_data))
        # print('length of sorted data is: {}'.format(len(sorted_data)))
        self._lower_quart = sorted_data[int((self._sw + 1) / 4)]
        # print('lower quartile is: {}'.format(self._lower_quart))

        self._upper_quart = sorted_data[int(3 * ((self._sw + 1) / 4))]
        self._inter_quart_range = int(self._upper_quart - self._lower_quart)
        # print(self._lower_quart, self._upper_quart, self._inter_quart_range)
