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

    def fuse_metrics(self, m_last, mf_list):
        count = 0
        for m_list in mf_list:

            if count == 0:
                # print('Last m is: {}, the first m in list is: {}'.format(m_last, m_list))
                result = m_last.combine_disjunctive(m_list)
                # print(result)
                result = self.process_ds(result)
                m = MassFunction(result)
                count += 1
                # print(m)
            # elif count == len(MF_list):
            #     return m
            else:
                # print('Last m is: {}, the first m in list is: {}'.format(m, m_list))
                result = m.combine_disjunctive(m_list)
                # print(result)
                result = self.process_ds(result)
                m = MassFunction(result)
                # print(m)
                count += 1
        return m
