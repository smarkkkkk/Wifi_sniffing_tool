
class DempsterShafer:

    # def __init__(self, normal, attack, uncert):
        # self._n = normal
        # self._a = attack
        # self._u = uncert

    def _combine(self, mass_function, rule, normalization, sample_count, importance_sampling):
        """Helper method for combining two or more mass functions."""
        combined = self
        if isinstance(mass_function, DempsterShafer):
            mass_function = [mass_function] # wrap single mass function
        for m in mass_function:
            if not isinstance(m, DempsterShafer):
                raise TypeError("expected type MassFunction but got %s; make sure to use keyword arguments "
                                "for anything other than mass functions" % type(m))
            if sample_count is None:
                combined = combined._combine_deterministic(m, rule)
            else:
                if importance_sampling and normalization:
                    combined = combined._combine_importance_sampling(m, sample_count)
                else:
                    combined = combined._combine_direct_sampling(m, rule, sample_count)
        if normalization:
            return combined.normalize()
        else:
            return combined

    def combine_disjunctive(self, mass_function, sample_count=None):
        """
        Disjunctively combines the mass function with another mass function and returns the combination as a new mass function.

        The other mass function is assumed to be defined over the same frame of discernment.
        If 'mass_function' is not of type MassFunction, it is assumed to be an iterable containing multiple mass functions that are iteratively combined.

        If 'sample_count' is not None, the true combination is approximated using the specified number of samples.
        """
        return self._combine(mass_function, rule=lambda s1, s2: s1 | s2, normalization=False, sample_count=sample_count,
                             importance_sampling=False)

    def _combine_deterministic(self, mass_function, rule):
        """Helper method for deterministically combining two mass functions."""
        combined = DempsterShafer()
        for (h1, v1) in self.items():
            for (h2, v2) in mass_function.items():
                combined[rule(h1, h2)] += v1 * v2
        return combined

    @staticmethod
    def _convert(hypothesis):
        """Convert hypothesis to a 'frozenset' in order to make it hashable."""
        if isinstance(hypothesis, frozenset):
            return hypothesis
        else:
            return frozenset(hypothesis)

    def __getitem__(self, hypothesis):
        return dict.__getitem__(self, DempsterShafer._convert(hypothesis))


