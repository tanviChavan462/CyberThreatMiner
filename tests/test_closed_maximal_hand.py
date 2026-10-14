"""
Hand-built test for Closed and Maximal Itemset correctness.
Validates the downward-closure and lossless compression properties on an explicit textbook example.
"""
import pytest
from backend.algorithms.apriori import AprioriMiner
from backend.algorithms.itemsets import find_closed_itemsets, find_maximal_itemsets


@pytest.fixture
def textbook_dataset():
    """
    Transactions:
    T1: {A, B}
    T2: {B, C, D}
    T3: {A, B, C, D}
    T4: {A, B, D}
    T5: {A, B, C, D}
    N = 5
    """
    return [
        {"A", "B"},
        {"B", "C", "D"},
        {"A", "B", "C", "D"},
        {"A", "B", "D"},
        {"A", "B", "C", "D"}
    ]


def test_hand_built_closed_and_maximal(textbook_dataset):
    """
    At min_support = 0.4 (support count >= 2):
    Itemset counts:
    {A}: 4/5 (T1, T3, T4, T5) = 0.8
    {B}: 5/5 (T1, T2, T3, T4, T5) = 1.0 -> Closed: {B} has sup 1.0, no superset has sup 1.0!
    {C}: 3/5 (T2, T3, T5) = 0.6
    {D}: 4/5 (T2, T3, T4, T5) = 0.8
    {A, B}: 4/5 (T1, T3, T4, T5) = 0.8 -> {A} has sup 0.8, superset {A, B} has sup 0.8, so {A} is NOT closed!
    {B, C}: 3/5 (T2, T3, T5) = 0.6 -> {C} has sup 0.6, superset {B, C} has sup 0.6, so {C} is NOT closed!
    {B, D}: 4/5 (T2, T3, T4, T5) = 0.8 -> {D} has sup 0.8, superset {B, D} has sup 0.8, so {D} is NOT closed!
    {C, D}: 3/5 (T2, T3, T5) = 0.6
    {A, B, C}: 2/5 (T3, T5) = 0.4
    {A, B, D}: 3/5 (T3, T4, T5) = 0.6
    {B, C, D}: 3/5 (T2, T3, T5) = 0.6
    {A, B, C, D}: 2/5 (T3, T5) = 0.4 -> Maximal! No frequent superset exists.
    """
    miner = AprioriMiner()
    frequent, _ = miner.mine(textbook_dataset, min_support=0.4, max_len=4)
    closed = find_closed_itemsets(frequent)
    maximal = find_maximal_itemsets(frequent)

    # 1. {A} has support 0.8, but {A, B} also has support 0.8. Thus {A} is NOT closed.
    assert frozenset(["A"]) not in closed

    # 2. {B} has support 1.0, and no superset has support 1.0. Thus {B} IS closed.
    assert frozenset(["B"]) in closed
    assert closed[frozenset(["B"])] == 1.0

    # 3. {A, B, C, D} is maximal because it is frequent and has no superset in the item universe
    assert frozenset(["A", "B", "C", "D"]) in maximal

    # 4. Mathematical theorem: Every maximal itemset MUST be closed
    for m in maximal:
        assert m in closed
        assert closed[m] == frequent[m]

    # 5. Mathematical theorem: Every closed itemset must be frequent
    for c in closed:
        assert c in frequent

    # 6. Lossless compression check: support of any frequent itemset S
    # equals max(support of closed itemsets that are supersets of S)
    for s, sup in frequent.items():
        supersets_sup = [c_sup for c, c_sup in closed.items() if s.issubset(c)]
        assert max(supersets_sup) == pytest.approx(sup)
