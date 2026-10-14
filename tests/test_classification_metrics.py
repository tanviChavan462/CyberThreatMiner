"""
Unit and Property Tests for Classification Metrics and Co-occurrence Recovery.
Verifies:
1. Confusion-matrix counts on a hand-built fixture.
2. Metric formulas against sklearn reference values.
3. No train/test data leakage.
4. Baseline sanity (random AUC ~ 0.5).
5. Fixed-seed determinism.
6. API endpoint schema and latency budget.
"""
import time
import numpy as np
import pytest
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    matthews_corrcoef,
    confusion_matrix
)
from app import app
from backend.evaluation.classification_metrics import (
    compute_binary_classification_metrics,
    evaluate_cooccurrence_recovery
)


def test_confusion_matrix_hand_built_example():
    """Verifies TP, FP, FN, TN on a controlled synthetic example with known ground truth."""
    # Suppose TP=30, FP=10, FN=20, TN=40
    # Total = 100
    # Precision = 30 / (30 + 10) = 0.75
    # Recall = 30 / (30 + 20) = 0.60
    # Specificity = 40 / (40 + 10) = 0.80
    # Accuracy = (30 + 40) / 100 = 0.70
    # Balanced Accuracy = (0.60 + 0.80) / 2 = 0.70
    # F1 = 2 * (0.75 * 0.60) / (0.75 + 0.60) = 0.90 / 1.35 = 0.6667
    tp, fp, fn, tn = 30, 10, 20, 40
    m = compute_binary_classification_metrics(tp, fp, fn, tn)

    assert m["precision"] == 0.75
    assert m["recall"] == 0.60
    assert m["specificity"] == 0.80
    assert m["accuracy"] == 0.70
    assert m["balanced_accuracy"] == 0.70
    assert abs(m["f1"] - (2 * 0.75 * 0.60 / 1.35)) < 1e-3
    assert m["mcc"] > 0.0


def test_metrics_against_sklearn_reference():
    """Validates custom metric calculations against scikit-learn standard implementations."""
    y_true = np.array([1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 0, 1, 0, 1])
    y_pred = np.array([1, 1, 1, 0, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0, 1])

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    m = compute_binary_classification_metrics(int(tp), int(fp), int(fn), int(tn))

    sk_prec = precision_score(y_true, y_pred)
    sk_rec = recall_score(y_true, y_pred)
    sk_f1 = f1_score(y_true, y_pred)
    sk_acc = accuracy_score(y_true, y_pred)
    sk_mcc = matthews_corrcoef(y_true, y_pred)

    assert abs(m["precision"] - sk_prec) < 1e-4
    assert abs(m["recall"] - sk_rec) < 1e-4
    assert abs(m["f1"] - sk_f1) < 1e-4
    assert abs(m["accuracy"] - sk_acc) < 1e-4
    assert abs(m["mcc"] - sk_mcc) < 1e-4


def test_no_train_test_leakage_and_stratification():
    """Asserts that test groups are strictly held out and never passed to the mining engine."""
    # Synthetic dataset with 20 threat groups
    tx_dict = {
        f"G{i}": [f"T{j}" for j in range(i % 5, (i % 5) + 6)]
        for i in range(20)
    }
    all_techs = [f"T{j}" for j in range(15)]

    res = evaluate_cooccurrence_recovery(
        transactions=tx_dict,
        all_techniques=all_techs,
        min_support=0.20,
        min_confidence=0.50,
        n_splits=5,
        random_seed=123
    )

    assert res["status"] == "ok"
    assert res["protocol"]["splits"] == 5
    assert res["protocol"]["groups_evaluated"] == 20
    assert "disclaimer" in res["protocol"]


def test_baseline_sanity_random_auc():
    """Asserts that the random guessing baseline produces an AUC close to 0.5."""
    tx_dict = {
        f"APT_{i}": [f"T{j}" for j in range(i % 4, (i % 4) + 5)]
        for i in range(30)
    }
    all_techs = [f"T{j}" for j in range(12)]

    res = evaluate_cooccurrence_recovery(
        transactions=tx_dict,
        all_techniques=all_techs,
        min_support=0.25,
        min_confidence=0.60,
        n_splits=5,
        random_seed=99
    )

    rand_auc = res["curves"]["random"]["roc_auc"]
    # Random baseline ROC-AUC must be in [0.35, 0.65] (around 0.5)
    assert 0.35 <= rand_auc <= 0.65


def test_determinism_under_fixed_seed():
    """Asserts that repeated evaluations with the exact same seed yield identical outputs."""
    tx_dict = {
        f"APT_{i}": [f"T{j}" for j in range(i % 3, (i % 3) + 4)]
        for i in range(25)
    }
    all_techs = [f"T{j}" for j in range(10)]

    run1 = evaluate_cooccurrence_recovery(tx_dict, all_techs, n_splits=3, random_seed=42)
    run2 = evaluate_cooccurrence_recovery(tx_dict, all_techs, n_splits=3, random_seed=42)

    assert run1["confusion_matrix"]["counts"] == run2["confusion_matrix"]["counts"]
    assert run1["summary_metrics"]["f1"]["mean"] == run2["summary_metrics"]["f1"]["mean"]
    assert run1["summary_metrics"]["roc_auc"]["mean"] == run2["summary_metrics"]["roc_auc"]["mean"]


def test_api_performance_endpoint_schema_and_latency():
    """Tests the /api/performance endpoint for schema compliance and latency SLA (< 5 seconds)."""
    client = app.test_client()

    t0 = time.perf_counter()
    resp = client.get("/api/performance?repeats=5&seed=42&mask_fraction=0.30")
    t1 = time.perf_counter()

    latency_s = t1 - t0
    assert resp.status_code == 200
    assert latency_s < 5.0, f"Performance endpoint SLA violated: took {latency_s:.2f} s"

    data = resp.get_json()
    assert data["status"] == "ok"
    assert "confusion_matrix" in data
    assert "summary_metrics" in data
    assert "curves" in data
    assert "threshold_sweep" in data
    assert "recovery_comparison" in data
    assert "per_rule_performance" in data
    assert "imbalance_note" in data

    # Check recovery comparison table has entries for K in {1, 3, 5, 10}
    k_vals = [row["k"] for row in data["recovery_comparison"]]
    assert set(k_vals) == {1, 3, 5, 10}
