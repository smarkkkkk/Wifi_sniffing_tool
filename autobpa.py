import numpy as np
from packetstatistics import PacketStatistics

class AutoBPA(PacketStatistics):
    alf = 0

    def __init__(self, data_set):
        super().__init__(sw, median, lower_quart, upper_quart, inter_quart_range)
        
        self.initial_data = data_set

    # alpha is not needed for IEEE journal N, A, U calculations
    # def alpha(self, data):
    # F = statistics.mode(self.initial_data)
    # a = math.degrees(math.acos(F / (math.sqrt(max(data) + (F^2)) )))


    def normal(self, value):
        # This will use quartiles from a box and whisker plot

    #def attack(self):
        # Euclidean distance of current value from reference point and reference to max value
    #def uncertainty(self):
        # Min of N and A divided by Max of N and A




