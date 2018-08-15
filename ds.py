from pyds.pyds import MassFunction


class DempsterShafer(MassFunction):

    def __init__(self, mass_dict, normal, attack, uncert):
        super().__init__(mass_dict)
        self._n = normal
        self._a = attack
        self._u = uncert

    def process_ds(self, frozen_mass_func):
        list_mass_func = list(frozen_mass_func.items())







