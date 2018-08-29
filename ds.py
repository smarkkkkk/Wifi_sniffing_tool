from pyds.pyds import MassFunction


class DempsterShafer:

    @staticmethod
    def process_ds(frozen_mass_func):
        # list_mass_func = list(frozen_mass_func.items())

        ds_dict = {}

        conflict = 1 / (1 - frozen_mass_func['a', 'n'])
        ds_dict['n'] = conflict * (frozen_mass_func['n'] + frozen_mass_func['n', 'u'])
        ds_dict['a'] = conflict * (frozen_mass_func['a'] + frozen_mass_func['a', 'u'])
        ds_dict['u'] = conflict * frozen_mass_func['u']

        # max(ds_dict.keys(), key=(lambda key: ds_dict[key]))
        return ds_dict
