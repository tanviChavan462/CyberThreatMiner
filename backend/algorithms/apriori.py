"""
Apriori Algorithm implemented from first principles.
Includes:
- Level-wise candidate generation (Ck) via (k-1)-way joins.
- Downward closure property (Apriori principle) subset pruning.
- Comprehensive diagnostic logs for educational and laboratory visualization.
"""
from typing import List, Set, Dict, FrozenSet, Tuple, Any, Optional
import time


class AprioriMiner:
    """
    Classic level-wise Apriori itemset mining algorithm.
    """

    def __init__(self):
        self.logs: List[Dict[str, Any]] = []

    def mine(
        self,
        transactions: List[Set[str]],
        min_support: float,
        max_len: Optional[int] = None
    ) -> Tuple[Dict[FrozenSet[str], float], List[Dict[str, Any]]]:
        """
        Mines all frequent itemsets satisfying min_support.

        Args:
            transactions: List of sets representing transaction baskets.
            min_support: Minimum support threshold in [0, 1].
            max_len: Optional maximum itemset length k.

        Returns:
            Tuple of:
            - Dict mapping FrozenSet[item] to support float.
            - List of per-level step diagnostic logs.
        """
        n_tx = len(transactions)
        if n_tx == 0:
            return {}, []

        min_count = min_support * n_tx
        self.logs = []
        all_frequent: Dict[FrozenSet[str], float] = {}

        start_time = time.perf_counter()

        # Level 1: Count single item frequencies (C1 -> L1)
        item_counts: Dict[str, int] = {}
        for tx in transactions:
            for item in tx:
                item_counts[item] = item_counts.get(item, 0) + 1

        l1: Dict[FrozenSet[str], int] = {}
        for item, count in item_counts.items():
            if count >= min_count:
                f_item = frozenset([item])
                l1[f_item] = count
                all_frequent[f_item] = count / n_tx

        self.logs.append({
            "k": 1,
            "candidates_generated": len(item_counts),
            "pruned_by_apriori": 0,
            "frequent_kept": len(l1),
            "description": f"Level 1: {len(item_counts)} candidate single items scanned; {len(l1)} met min_support >= {min_support:.2f}."
        })

        current_l = l1
        k = 2

        # Level k loop: generate C_k from L_{k-1}, prune, scan database
        while current_l and (max_len is None or k <= max_len):
            prev_itemsets = list(current_l.keys())
            c_k_candidates: Set[FrozenSet[str]] = set()
            pruned_count = 0

            # Candidate generation: join step L_{k-1} x L_{k-1}
            n_prev = len(prev_itemsets)
            for i in range(n_prev):
                for j in range(i + 1, n_prev):
                    set1 = prev_itemsets[i]
                    set2 = prev_itemsets[j]
                    union = set1 | set2
                    if len(union) == k:
                        # Pruning step: downward closure property
                        # Every (k-1)-subset of union must be in current_l
                        all_subsets_frequent = True
                        for item in union:
                            subset = union - frozenset([item])
                            if subset not in current_l:
                                all_subsets_frequent = False
                                break

                        if all_subsets_frequent:
                            c_k_candidates.add(union)
                        else:
                            pruned_count += 1

            candidates_generated = len(c_k_candidates) + pruned_count
            if not c_k_candidates:
                self.logs.append({
                    "k": k,
                    "candidates_generated": candidates_generated,
                    "pruned_by_apriori": pruned_count,
                    "frequent_kept": 0,
                    "description": f"Level {k}: 0 valid candidates passed downward closure. Halting."
                })
                break

            # Count support of C_k in transactions
            candidate_counts: Dict[FrozenSet[str], int] = {c: 0 for c in c_k_candidates}
            for tx in transactions:
                # Fast subset check: only check candidates whose items might be in tx
                for cand in c_k_candidates:
                    if cand.issubset(tx):
                        candidate_counts[cand] += 1

            # Filter frequent L_k
            l_k: Dict[FrozenSet[str], int] = {}
            for cand, count in candidate_counts.items():
                if count >= min_count:
                    l_k[cand] = count
                    all_frequent[cand] = count / n_tx

            self.logs.append({
                "k": k,
                "candidates_generated": candidates_generated,
                "pruned_by_apriori": pruned_count,
                "frequent_kept": len(l_k),
                "description": f"Level {k}: Generated {candidates_generated} candidates, pruned {pruned_count} via downward closure, kept {len(l_k)} frequent itemsets."
            })

            current_l = l_k
            k += 1

        elapsed_ms = (time.perf_counter() - start_time) * 1000.0
        return all_frequent, self.logs
