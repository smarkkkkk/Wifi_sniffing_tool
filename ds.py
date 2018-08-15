from pyds.pyds import MassFunction


class DempsterShafer(MassFunction):

    def __init__(self, mass_dict, normal, attack, uncert, conflict):
        super().__init__(mass_dict)
        self._n = normal
        self._a = attack
        self._u = uncert
        self._conflict = conflict

    def process_ds(self, frozen_mass_func):
        list_mass_func = list(frozen_mass_func.items())

        self._conflict = 1 / (1 - list_mass_func[1][1])

        self._n = self._conflict * (list_mass_func[3][1] + list_mass_func[4][1])

        self._a = self._conflict * (list_mass_func[0][1] + list_mass_func[2][1])

        self._u = self._conflict * list_mass_func[5][1]

        








