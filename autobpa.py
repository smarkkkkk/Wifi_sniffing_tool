import numpy as np
from packetstatistics import PacketStatistics


class AutoBPA(PacketStatistics):
    # alf = 0

    # Putting new variables before kwargs seems to be allowed.
    # **kwargs is a dictionary of keyword arguments that can take on any
    # number of key, value pairs. No default values are set in Statistics class
    def __init__(self, normal_bpa, attack_bpa, uncertainty_bpa, **kwargs):
        super().__init__(**kwargs)
        self._normal_bpa = normal_bpa
        self._attack_bpa = attack_bpa
        self._uncertainty_bpa = uncertainty_bpa

    # alpha is not needed for IEEE journal N, A, U calculations
    # def alpha(self, data):
    # F = statistics.mode(self.initial_data)
    # a = math.degrees(math.acos(F / (math.sqrt(max(data) + (F^2)) )))

    def normal(self, value):
        # This will use quartiles from a box and whisker plot in PacketStatistics
        # to assign a BPA for normal based on the metric value
        min = self._lower_quart - (1.5 * self._inter_quart_range)
        max = self._upper_quart + (1.5 * self._inter_quart_range)

        if self._lower_quart < value < self._upper_quart:
            self._normal_bpa = 0.4
        elif min < value < self._lower_quart or self._upper_quart < value < max:
                self._normal_bpa = 0.3
        else:
            self._normal_bpa = 0.75

        return self._normal_bpa


    #def attack(self):
        # Euclidean distance of current value from reference point and reference to max value
    #def uncertainty(self):
        # Min of N and A divided by Max of N and A




