"""
Filters and properties for Frequent, Closed, and Maximal Itemsets.
- Closed itemset: No proper superset has identical support.
- Maximal itemset: No proper superset is frequent (satisfies min_support).
"""
from typing import Dict, FrozenSet, Set, List, Tuple


def find_closed_itemsets(frequent_itemsets: Dict[FrozenSet[str], float]) -> Dict[FrozenSet[str], float]:
    """
    Identifies all closed itemsets from a dictionary of frequent itemsets.
    An itemset X is closed iff no proper superset Y > X has support(Y) == support(X).
    """
    closed: Dict[FrozenSet[str], float] = {}
    itemset_list = list(frequent_itemsets.items())
    # Sort by length descending for quick superset check
    itemset_list.sort(key=lambda x: len(x[0]), reverse=True)

    for itemset, sup in itemset_list:
        is_closed = True
        for other_itemset, other_sup in itemset_list:
            if len(other_itemset) > len(itemset) and itemset.issubset(other_itemset):
                # Check if superset has equal support (within floating point epsilon)
                if abs(other_sup - sup) < 1e-9:
                    is_closed = False
                    break
        if is_closed:
            closed[itemset] = sup

    return closed


def find_maximal_itemsets(frequent_itemsets: Dict[FrozenSet[str], float]) -> Dict[FrozenSet[str], float]:
    """
    Identifies all maximal itemsets from a dictionary of frequent itemsets.
    An itemset X is maximal iff no proper superset Y > X exists in frequent_itemsets.
    """
    maximal: Dict[FrozenSet[str], float] = {}
    all_sets = list(frequent_itemsets.keys())
    all_sets.sort(key=len, reverse=True)

    for itemset in all_sets:
        is_maximal = True
        for other in all_sets:
            if len(other) > len(itemset) and itemset.issubset(other):
                is_maximal = False
                break
        if is_maximal:
            maximal[itemset] = frequent_itemsets[itemset]

    return maximal
