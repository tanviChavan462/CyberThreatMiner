"""
API integration and edge-case tests using Flask test client.
Tests responses, edge conditions (0 itemsets, invalid queries, group 404),
and ensures disclaimer is present across results.
"""
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_api_summary(client):
    res = client.get("/api/summary")
    assert res.status_code == 200
    data = res.get_json()
    assert data["groups"] == 167
    assert data["techniques"] == 203
    assert "top_techniques" in data
    assert "tactic_distribution" in data
    assert "DISCLAIMER" in data["disclaimer"]


def test_api_mine_defaults(client):
    res = client.get("/api/mine?min_support=0.3&min_conf=0.7&min_lift=1.0")
    assert res.status_code == 200
    data = res.get_json()
    assert data["algorithm"] == "apriori"
    assert "rules" in data
    assert "itemsets" in data
    if data["rules"]:
        r0 = data["rules"][0]
        assert "confidence" in r0
        assert "lift" in r0
        assert "p_value" in r0
        assert "q_value" in r0
        assert "plain_english" in r0


def test_api_mine_fp_growth_and_eclat(client):
    res_fp = client.get("/api/mine?algorithm=fp_growth&min_support=0.35&min_conf=0.7")
    assert res_fp.status_code == 200
    assert res_fp.get_json()["algorithm"] == "fp_growth"

    res_ec = client.get("/api/mine?algorithm=eclat&min_support=0.35&min_conf=0.7")
    assert res_ec.status_code == 200
    assert res_ec.get_json()["algorithm"] == "eclat"


def test_api_mine_edge_case_no_itemsets(client):
    # Extremely high min_support (0.99) should return 0 itemsets cleanly without crash
    res = client.get("/api/mine?min_support=0.99&min_conf=0.99")
    assert res.status_code == 200
    data = res.get_json()
    assert data["total_frequent_itemsets"] == 0
    assert data["rules_count"] == 0
    assert data["itemsets"] == []
    assert data["rules"] == []


def test_api_clusters(client):
    res = client.get("/api/clusters?k=3&method=kmeans")
    assert res.status_code == 200
    data = res.get_json()
    assert data["k"] == 3
    assert "silhouette" in data
    assert "pca_points" in data
    assert len(data["clusters"]) == 3


def test_api_cooccur(client):
    # Valid techniques
    res = client.get("/api/cooccur?techniques=T1059,T1105")
    assert res.status_code == 200
    data = res.get_json()
    assert "cooccurring_techniques" in data
    assert "DISCLAIMER" in data["disclaimer"]

    # Empty query edge case
    res_empty = client.get("/api/cooccur?techniques=")
    assert res_empty.status_code == 400
    assert "error" in res_empty.get_json()


def test_api_fingerprint(client):
    res = client.get("/api/fingerprint?group=APT28")
    assert res.status_code == 200
    data = res.get_json()
    assert data["group"] == "APT28"
    assert "similar_groups" in data
    assert "tactic_distribution" in data

    # Non-existent group
    res_404 = client.get("/api/fingerprint?group=NonExistentGroup999")
    assert res_404.status_code == 404


def test_api_network(client):
    res = client.get("/api/network?min_support=0.25&min_conf=0.7&min_lift=1.2")
    assert res.status_code == 200
    data = res.get_json()
    assert "elements" in data
    assert "nodes" in data["elements"]
    assert "edges" in data["elements"]
