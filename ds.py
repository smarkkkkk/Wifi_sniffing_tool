from pyds.pyds import MassFunction


class DempsterShafer:
    """
    This class is used to handle all Dempster Shafer functionality, mainly, processing the result of
    MassFunctions from the pyds module and fusing the metrics.
    """

    @staticmethod
    def process_ds(frozen_mass_func):
        """
        This function processes the fused metrics into a format of N, A, U.

        :param frozen_mass_func: frozenset containing all combinations of N, A, U for the fuse
        :return: ds_dict: dictionary containing N, A, U for the fuse
        """

        ds_dict = {}

        conflict = 1 / (1 - frozen_mass_func['a', 'n'])
        ds_dict['n'] = conflict * (frozen_mass_func['n'] + frozen_mass_func['n', 'u'])
        ds_dict['a'] = conflict * (frozen_mass_func['a'] + frozen_mass_func['a', 'u'])
        ds_dict['u'] = conflict * frozen_mass_func['u']

        # max(ds_dict.keys(), key=(lambda key: ds_dict[key]))
        return ds_dict

    def fuse_metrics(self, m_last, mf_list):
        """
        This function processes a list of MassFunctions (one for each metric) and fuses them using
        combine_disjunctive from the pyds module to produce the N, A, U probability for the metric fuse

        :param m_last: the MassFunction of the last metric
        :param mf_list: list containing MassFunctions for every other metric
        :return: m: final N, A, U dictionary containing final probabilities for fused metrics
        """
        
        count = 0
        for m_list in mf_list:
            if count == 0:
                result = m_last.combine_disjunctive(m_list)
                result = self.process_ds(result)
                m = MassFunction(result)
                count += 1
            else:
                result = m.combine_disjunctive(m_list)
                result = self.process_ds(result)
                m = MassFunction(result)
                count += 1

        return m
