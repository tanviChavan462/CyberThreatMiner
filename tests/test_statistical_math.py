"""
Statistical Validation Math & Determinism Tests:
1. Fisher's Exact Test against scipy.stats reference values.
2. Benjamini-Hochberg FDR q-values against reference values.
3. Permutation p-value floor (>= 1 / (N_perms + 1)) and string formatting.
4. Bootstrap determinism with fixed seed.
"""
import pytest
import numpy as np
import scipy.stats as stats
from backend.algorithms.rules import AssociationRule
from backend.evaluation.statistical_tests import (
    compute_fisher_exact,
    benjamini_hochberg_fdr,
    PermutationNullModel
)
from backend.evaluation.bootstrap import evaluate_bootstrap_stability


def test_fisher_exact_against_scipy():
    """Validates compute_fisher_exact against direct scipy.stats.fisher_exact."""
    rule = AssociationRule(
        antecedent=frozenset(["T1059"]),
        consequent=frozenset(["T1105"]),
        support=0.35,
        confidence=0.75,
        lift=1.8,
        leverage=0.15,
        conviction=2.5,
        zhang=0.6,
        jaccard=0.5,
        kulczynski=0.7,
        cosine=0.7,
        all_confidence=0.6,
        support_a=0.4667,
        support_b=0.4167
    )
    n = 120
    p_computed, neg_log10_p = compute_fisher_exact(rule, n)

    # Reference calculation directly from contingency table
    n_ab = int(round(rule.support * n))
    n_a = int(round(rule.support_a * n))
    n_b = int(round(rule.support_b * n))
    table = [
        [n_ab, max(0, n_a - n_ab)],
        [max(0, n_b - n_ab), max(0, n - n_a - n_b + n_ab)]
    ]
    _, p_ref = stats.fisher_exact(table, alternative="greater")

    assert pytest.approx(p_computed, rel=1e-5) == p_ref
    assert neg_log10_p > 0
    assert np.isfinite(neg_log10_p)


def test_benjamini_hochberg_fdr():
    """Validates BH-FDR against reference calculation without rounding loss."""
    raw_p = [0.001, 0.01, 0.04, 0.12, 0.50]
    q_vals, neg_log_q = benjamini_hochberg_fdr(raw_p)

    m = len(raw_p)
    # Manual BH:
    # rank 1: p=0.001 -> (5/1)*0.001 = 0.005
    # rank 2: p=0.01  -> (5/2)*0.01  = 0.025
    # rank 3: p=0.04  -> (5/3)*0.04  = 0.066667
    # rank 4: p=0.12  -> (5/4)*0.12  = 0.15
    # rank 5: p=0.50  -> (5/5)*0.50  = 0.50
    assert pytest.approx(q_vals[0], rel=1e-4) == 0.005
    assert pytest.approx(q_vals[1], rel=1e-4) == 0.025
    assert pytest.approx(q_vals[2], rel=1e-4) == 0.066667
    assert pytest.approx(q_vals[3], rel=1e-4) == 0.15
    assert pytest.approx(q_vals[4], rel=1e-4) == 0.50

    for q, nlq in zip(q_vals, neg_log_q):
        assert pytest.approx(nlq, rel=1e-4) == -np.log10(q)


def test_permutation_p_value_floor():
    """Validates that empirical permutation p-value never displays 0 and respects floor 1/(N+1)."""
    # Create simple binary matrix
    rng = np.random.default_rng(42)
    binary_mat = rng.choice([False, True], size=(50, 20), p=[0.85, 0.15])
    item_names = [f"T{i}" for i in range(20)]

    null_model = PermutationNullModel(binary_mat, item_names, seed=42)

    # A rule with impossible observed lift (e.g. 999.0) will have 0 exceedances
    rule_extreme = AssociationRule(
        antecedent=frozenset(["T0"]),
        consequent=frozenset(["T1"]),
        support=0.2,
        confidence=0.8,
        lift=999.0,
        leverage=0.1,
        conviction=5.0,
        zhang=0.8,
        jaccard=0.5,
        kulczynski=0.7,
        cosine=0.7,
        all_confidence=0.6,
        support_a=0.3,
        support_b=0.3
    )

    n_perms = 100
    evaluated = null_model.evaluate_rules_under_null([rule_extreme], n_permutations=n_perms)
    r = evaluated[0]

    expected_floor = 1.0 / (n_perms + 1)
    assert r.permutation_p_value == pytest.approx(expected_floor)
    assert r.permutation_p_value > 0.0  # Must NEVER be zero
    assert "p <" in r.permutation_p_str or "p =" in r.permutation_p_str


def test_bootstrap_determinism_with_seed():
    """Validates that evaluate_bootstrap_stability produces identical results across runs with the same seed."""
    transactions = [
        {"T1059", "T1082", "T1105"},
        {"T1059", "T1082"},
        {"T1059", "T1105"},
        {"T1082", "T1105"},
        {"T1059", "T1082", "T1105"},
        {"T1059", "T1082"},
        {"T1082", "T1105"},
        {"T1059", "T1082", "T1105"}
    ]
    rule = AssociationRule(
        antecedent=frozenset(["T1059"]),
        consequent=frozenset(["T1082"]),
        support=0.5,
        confidence=0.8,
        lift=1.2,
        leverage=0.1,
        conviction=2.0,
        zhang=0.5,
        jaccard=0.6,
        kulczynski=0.7,
        cosine=0.7,
        all_confidence=0.6,
        support_a=0.625,
        support_b=0.75
    )

    res1 = evaluate_bootstrap_stability([rule], transactions, min_support=0.3, min_confidence=0.5, n_bootstraps=50, random_seed=42)
    stab1 = res1[0].stability_pct

    # Re-instantiate rule with empty fields
    rule2 = AssociationRule(
        antecedent=frozenset(["T1059"]),
        consequent=frozenset(["T1082"]),
        support=0.5,
        confidence=0.8,
        lift=1.2,
        leverage=0.1,
        conviction=2.0,
        zhang=0.5,
        jaccard=0.6,
        kulczynski=0.7,
        cosine=0.7,
        all_confidence=0.6,
        support_a=0.625,
        support_b=0.75
    )
    res2 = evaluate_bootstrap_stability([rule2], transactions, min_support=0.3, min_confidence=0.5, n_bootstraps=50, random_seed=42)
    stab2 = res2[0].stability_pct

    assert stab1 == stab2
    assert 0.0 <= stab1 <= 100.0
