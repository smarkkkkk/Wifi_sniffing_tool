from pyds.pyds import MassFunction


class DempsterShafer(MassFunction):

    def __init__(self, mass_dict, normal, attack, uncert, conflict):
        super().__init__(mass_dict)
        self._n = normal
        self._a = attack
        self._u = uncert
        self._conflict = conflict

    @staticmethod
    def process_ds(frozen_mass_func):
        list_mass_func = list(frozen_mass_func.items())

        ds_dict = {}

        conflict = 1 / (1 - list_mass_func[1][1])

        ds_dict['n'] = conflict * (list_mass_func[3][1] + list_mass_func[4][1])

        ds_dict['a'] = conflict * (list_mass_func[0][1] + list_mass_func[2][1])

        ds_dict['u'] = conflict * list_mass_func[5][1]

        return max(ds_dict.keys(), key=(lambda key: ds_dict[key]))
    










