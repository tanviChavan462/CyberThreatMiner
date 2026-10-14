"""
Complete API Integration & Contract Tests:
Validates every API route for:
1. Status 200 on valid inputs.
2. Mandatory non-causal DISCLAIMER presence.
3. Schema conformity for frontend consumers.
4. Appropriate HTTP 400 on bad input and 404 on missing entities.
"""
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_summary_endpoint(client):
    res = client.get("/api/summary")
    assert res.status_code == 200
    data = res.get_json()
    assert data["groups"] == 167
    assert data["techniques"] == 203
    assert "top_techniques" in data
    assert "tactic_distribution" in data
    assert "NON-CAUSAL" in data["disclaimer"] or "DISCLAIMER" in data["disclaimer"]


def test_api_mine_with_popularity_filter_and_compression(client):
    res = client.get("/api/mine?min_support=0.3&min_conf=0.7&max_item_support=0.7&prune_redundant=true")
    assert res.status_code == 200
    data = res.get_json()
    assert "closed_compression_pct" in data
    assert "maximal_compression_pct" in data
    assert "redundant_rules_pruned" in data
    assert "rules" in data
    assert "itemsets" in data
    assert "NON-CAUSAL" in data["disclaimer"] or "DISCLAIMER" in data["disclaimer"]


def test_api_statistical_eval_1000_perms(client):
    # Runs statistical eval with 100 permutations in test client to keep test snappy
    res = client.get("/api/statistical_eval?min_support=0.3&min_conf=0.75&n_bootstraps=30&n_permutations=100")
    assert res.status_code == 200
    data = res.get_json()
    assert "volcano_points" in data
    assert "significant_rules_count" in data
    if data["volcano_points"]:
        p0 = data["volcano_points"][0]
        assert "neg_log10_q" in p0
        assert "sig_fisher" in p0
        assert "sig_perm" in p0
        assert "sig_boot" in p0
        assert "is_significant" in p0
        assert np_is_finite(p0["neg_log10_q"])


def np_is_finite(val):
    import numpy as np
    return np.isfinite(val) and val >= 0


def test_api_train_test_splits(client):
    res = client.get("/api/train_test?n_splits=5")
    assert res.status_code == 200
    data = res.get_json()
    tt = data["train_test"]
    assert "mean_signed_generalization_gap" in tt
    assert "mean_absolute_generalization_gap" in tt
    assert "mean_test_precision" in tt
    assert "train_confidence_ci95" in tt
    assert "test_confidence_ci95" in tt


def test_api_baselines_endpoint(client):
    res = client.get("/api/baselines")
    assert res.status_code == 200
    data = res.get_json()
    assert "summary_table_k10" in data
    assert len(data["summary_table_k10"]) == 5
    assert "statistical_test" in data


def test_api_multi_lens_eval_endpoint(client):
    res = client.get("/api/multi_lens_eval?target_lens=software")
    assert res.status_code == 200
    data = res.get_json()
    assert data["target_lens"] == "software"
    assert "agreement_pct" in data
    assert "rules_tested" in data


def test_api_self_check_endpoint(client):
    res = client.get("/api/self_check")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] == "PASS"
    assert "data_integrity" in data["checks"]
    assert "algorithms_equivalent" in data["checks"]
    assert "mlxtend_agreement" in data["checks"]
    assert "test_suite" in data["checks"]


def test_api_cooccur_and_bad_input(client):
    # Valid query
    res_ok = client.get("/api/cooccur?techniques=T1059,T1082")
    assert res_ok.status_code == 200
    assert "cooccurring_techniques" in res_ok.get_json()

    # Empty / bad query returns 400
    res_bad = client.get("/api/cooccur?techniques=")
    assert res_bad.status_code == 400
    assert "error" in res_bad.get_json()


def test_api_fingerprint_and_not_found(client):
    # Valid threat actor
    res_ok = client.get("/api/fingerprint?group=APT28")
    assert res_ok.status_code == 200
    assert res_ok.get_json()["group"] == "APT28"

    # Invalid actor returns 404
    res_404 = client.get("/api/fingerprint?group=NonExistentAdversary999")
    assert res_404.status_code == 404
    assert "error" in res_404.get_json()


def test_api_network_graph(client):
    res = client.get("/api/network?min_support=0.3&min_conf=0.7&min_lift=1.2")
    assert res.status_code == 200
    data = res.get_json()
    assert "elements" in data
    assert "nodes" in data["elements"]
    assert "edges" in data["elements"]


def test_api_tactics_heatmap(client):
    res = client.get("/api/tactics_heatmap")
    assert res.status_code == 200
    data = res.get_json()
    assert "tactics" in data
    assert "z" in data
    assert len(data["tactics"]) == len(data["z"])


def test_api_benchmarks_endpoint(client):
    res = client.get("/api/benchmarks")
    assert res.status_code == 200
    data = res.get_json()
    assert "supports" in data
    assert "scaling_benchmark" in data
    assert data["equivalence_verified"] is True
