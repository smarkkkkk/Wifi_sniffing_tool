from packetstatistics import PacketStatistics


class AutoBPA(PacketStatistics):
    # alf = 0

    # Putting new variables before kwargs seems to be allowed.
    # **kwargs is a dictionary of keyword arguments that can take on any
    # number of key, value pairs. No default values are set in Statistics class
    def __init__(self, sw, **kwargs):
        super().__init__(**kwargs)
        self._sw = sw
        if 'normal_bpa' in kwargs: self._normal_bpa = kwargs['normal_bpa']
        if 'attack_bpa' in kwargs: self._attack_bpa = kwargs['attack_bpa']
        if 'uncertainty_bpa' in kwargs: self._uncertainty_bpa = kwargs['uncertainty_bpa']
        if 'adjustment_factor' in kwargs: self._adjust_bpa = kwargs['adjustment_factor']

    # alpha is not needed for IEEE journal N, A, U calculations
    # def alpha(self, data):
    # F = statistics.mode(self.initial_data)
    # a = math.degrees(math.acos(F / (math.sqrt(max(data) + (F^2)) )))

    def normal(self, value):
        # This will use quartiles from a box and whisker plot in PacketStatistics
        # to assign a BPA for normal based on the metric value
        min_val = self._lower_quart - (1.5 * self._inter_quart_range)
        max_val = self._upper_quart + (1.5 * self._inter_quart_range)

        if self._lower_quart < value < self._upper_quart:
            self._normal_bpa = 0.4
        elif min_val < value < self._lower_quart or self._upper_quart < value < max_val:
                self._normal_bpa = 0.3
        else:
            self._normal_bpa = 0.15
        print(value)
        return self._normal_bpa

    def attack(self):
        # Euclidean distance of current value from reference point and reference to max value
        self._attack_bpa = (self._dist_mean * 0.5) / self._dist_maxval

        return self._attack_bpa

    def uncertainty(self):
        # Min of N and A divided by Max of N and A
        if self._normal_bpa > self._attack_bpa:
            min_bpa = self._attack_bpa
            max_bpa = self._normal_bpa
        elif self._normal_bpa < self._attack_bpa:
            min_bpa = self._normal_bpa
            max_bpa = self._attack_bpa
        else:
            min_bpa, max_bpa = 0.5, 0.5

        self._uncertainty_bpa = min_bpa / max_bpa

        return self._uncertainty_bpa

    def adjustment_factor(self):
        # Calculate the adjustment factor to be applied to each bpa
        self._adjust_bpa = ((self._normal_bpa + self._attack_bpa + self._uncertainty_bpa) - 1) / 3

        return self._adjust_bpa





