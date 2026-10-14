"""
Train/Test Generalization Gap & Aggregation Tests:
Verifies:
1. Headline mean_generalization_gap and signed gap are consistent with per-fold values.
2. 95% confidence intervals are mathematically valid.
3. Rule precision on unseen groups is reported.
"""
import pytest
import numpy as np
from backend.evaluation.train_test import evaluate_train_test_split


@pytest.fixture
def transactions_sample():
    rng = np.random.default_rng(42)
    items = [f"T{i}" for i in range(25)]
    txs = []
    for _ in range(80):
        k = rng.integers(3, 10)
        txs.append(set(rng.choice(items, size=k, replace=False)))
    return txs


def test_train_test_gap_aggregation(transactions_sample):
    """Verifies that headline generalization gaps are exact means of per-split metrics."""
    res = evaluate_train_test_split(transactions_sample, min_support=0.15, min_confidence=0.5, n_splits=8, random_seed=42)

    assert "splits" in res
    assert len(res["splits"]) > 0

    splits = res["splits"]
    per_split_signed = [s["signed_generalization_gap"] for s in splits]
    per_split_abs = [s["absolute_generalization_gap"] for s in splits]
    per_split_prec = [s["mean_test_precision"] for s in splits]

    # Headline signed gap equals mean of per-split signed gaps
    assert pytest.approx(res["mean_signed_generalization_gap"], abs=1e-3) == float(np.mean(per_split_signed))

    # Headline absolute gap equals mean of per-split absolute gaps
    assert pytest.approx(res["mean_absolute_generalization_gap"], abs=1e-3) == float(np.mean(per_split_abs))
    assert pytest.approx(res["mean_generalization_gap"], abs=1e-3) == float(np.mean(per_split_abs))

    # Precision on unseen groups
    assert pytest.approx(res["mean_test_precision"], abs=1e-3) == float(np.mean(per_split_prec))
    assert 0.0 <= res["mean_test_precision"] <= 1.0

    # 95% Confidence interval sanity
    ci_signed = res["signed_generalization_gap_ci95"]
    assert ci_signed[0] <= res["mean_signed_generalization_gap"] <= ci_signed[1]

    ci_abs = res["absolute_generalization_gap_ci95"]
    assert ci_abs[0] <= res["mean_absolute_generalization_gap"] <= ci_abs[1]
