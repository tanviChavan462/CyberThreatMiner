"""
Eclat (Equivalence Class Clustering and along with Lattice Traversal) algorithm.
Uses vertical transaction representation (TID sets) and recursive set intersections.
"""
from typing import List, Set, Dict, FrozenSet, Tuple, Any, Optional


class EclatMiner:
    """Mines frequent itemsets using vertical TID-set intersections."""

    def __init__(self):
        pass

    def mine(
        self,
        transactions: List[Set[str]],
        min_support: float,
        max_len: Optional[int] = None
    ) -> Dict[FrozenSet[str], float]:
        """
        Mines frequent itemsets using Eclat.

        Args:
            transactions: List of sets representing transaction baskets.
            min_support: Minimum support threshold in [0, 1].
            max_len: Optional maximum itemset length k.

        Returns:
            Dict mapping FrozenSet[item] to support float.
        """
        n_tx = len(transactions)
        if n_tx == 0:
            return {}

        min_count = min_support * n_tx

        # Step 1: Invert horizontal transactions to vertical TID sets
        tid_sets: Dict[str, Set[int]] = {}
        for tid, tx in enumerate(transactions):
            for item in tx:
                tid_sets.setdefault(item, set()).add(tid)

        # Filter items meeting minimum support
        frequent_singletons = {
            item: tids for item, tids in tid_sets.items() if len(tids) >= min_count
        }

        results: Dict[FrozenSet[str], float] = {}

        # Add singletons
        for item, tids in frequent_singletons.items():
            f_item = frozenset([item])
            results[f_item] = len(tids) / n_tx

        # Step 2: Recursive DFS lattice traversal
        def recurse(
            prefix_items: List[Tuple[str, Set[int]]],
            current_prefix: FrozenSet[str]
        ):
            n_items = len(prefix_items)
            for i in range(n_items):
                item_i, tids_i = prefix_items[i]
                new_prefix = current_prefix | frozenset([item_i])
                suffix_candidates: List[Tuple[str, Set[int]]] = []

                if max_len is not None and len(new_prefix) >= max_len:
                    continue

                for j in range(i + 1, n_items):
                    item_j, tids_j = prefix_items[j]
                    intersected_tids = tids_i & tids_j

                    if len(intersected_tids) >= min_count:
                        cand_set = new_prefix | frozenset([item_j])
                        results[cand_set] = len(intersected_tids) / n_tx
                        suffix_candidates.append((item_j, intersected_tids))

                if suffix_candidates and (max_len is None or len(new_prefix) + 1 < max_len):
                    recurse(suffix_candidates, new_prefix)

        # Sort singletons for deterministic execution
        sorted_singletons = sorted(frequent_singletons.items(), key=lambda x: (-len(x[1]), x[0]))
        # We start pairwise combinations
        n_singles = len(sorted_singletons)
        for i in range(n_singles):
            item_i, tids_i = sorted_singletons[i]
            if max_len is not None and max_len < 2:
                break
            suffix_candidates: List[Tuple[str, Set[int]]] = []
            for j in range(i + 1, n_singles):
                item_j, tids_j = sorted_singletons[j]
                intersected = tids_i & tids_j
                if len(intersected) >= min_count:
                    cand_set = frozenset([item_i, item_j])
                    results[cand_set] = len(intersected) / n_tx
                    suffix_candidates.append((item_j, intersected))

            if suffix_candidates and (max_len is None or max_len > 2):
                recurse(suffix_candidates, frozenset([item_i]))

        return results
