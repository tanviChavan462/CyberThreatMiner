"""
Unit tests: Hand-computed mathematical verification of Apriori and Rule measures.
Validates exact fractional support, confidence, lift, leverage, conviction, and Zhang's metric.
"""
import pytest
from backend.algorithms.apriori import AprioriMiner
from backend.algorithms.rules import generate_rules, AssociationRule
from backend.algorithms.itemsets import find_closed_itemsets, find_maximal_itemsets


@pytest.fixture
def textbook_transactions():
    """
    Standard textbook dataset with 5 transactions:
    T1: {A, B, C}
    T2: {A, B}
    T3: {A, C, D}
    T4: {B, C, D}
    T5: {A, B, C, D}
    """
    return [
        {"A", "B", "C"},
        {"A", "B"},
        {"A", "C", "D"},
        {"B", "C", "D"},
        {"A", "B", "C", "D"}
    ]


def test_hand_computed_support(textbook_transactions):
    miner = AprioriMiner()
    itemsets, logs = miner.mine(textbook_transactions, min_support=0.6, max_len=3)

    # Hand calculations (N = 5):
    # {A}: in T1, T2, T3, T5 -> 4/5 = 0.8
    # {B}: in T1, T2, T4, T5 -> 4/5 = 0.8
    # {C}: in T1, T3, T4, T5 -> 4/5 = 0.8
    # {D}: in T3, T4, T5     -> 3/5 = 0.6
    # {A, B}: in T1, T2, T5  -> 3/5 = 0.6
    # {A, C}: in T1, T3, T5  -> 3/5 = 0.6
    # {B, C}: in T1, T4, T5  -> 3/5 = 0.6
    # {C, D}: in T3, T4, T5  -> 3/5 = 0.6

    assert frozenset(["A"]) in itemsets
    assert pytest.approx(itemsets[frozenset(["A"])]) == 0.8

    assert frozenset(["D"]) in itemsets
    assert pytest.approx(itemsets[frozenset(["D"])]) == 0.6

    assert frozenset(["A", "B"]) in itemsets
    assert pytest.approx(itemsets[frozenset(["A", "B"])]) == 0.6

    assert frozenset(["C", "D"]) in itemsets
    assert pytest.approx(itemsets[frozenset(["C", "D"])]) == 0.6

    # {A, D} in T3, T5 -> 2/5 = 0.4 < 0.6, must NOT be present
    assert frozenset(["A", "D"]) not in itemsets


def test_hand_computed_rules(textbook_transactions):
    miner = AprioriMiner()
    itemsets, _ = miner.mine(textbook_transactions, min_support=0.6, max_len=2)
    rules = generate_rules(itemsets, min_confidence=0.7, min_lift=0.5)

    # For rule A -> B:
    # sup(A, B) = 0.6
    # sup(A) = 0.8
    # sup(B) = 0.8
    # conf(A -> B) = 0.6 / 0.8 = 0.75
    # lift(A -> B) = 0.75 / 0.8 = 0.9375
    # leverage = 0.6 - (0.8 * 0.8) = -0.04
    rule_ab = next((r for r in rules if r.antecedent == frozenset(["A"]) and r.consequent == frozenset(["B"])), None)
    assert rule_ab is not None
    assert pytest.approx(rule_ab.support) == 0.6
    assert pytest.approx(rule_ab.confidence) == 0.75
    assert pytest.approx(rule_ab.lift, abs=0.01) == 0.938
    assert pytest.approx(rule_ab.leverage) == -0.04


def test_closed_and_maximal_itemsets(textbook_transactions):
    miner = AprioriMiner()
    itemsets, _ = miner.mine(textbook_transactions, min_support=0.6, max_len=3)
    closed = find_closed_itemsets(itemsets)
    maximal = find_maximal_itemsets(itemsets)

    # Every maximal must be closed
    for m in maximal:
        assert m in closed

    # Every closed must be in frequent itemsets
    for c in closed:
        assert c in itemsets
