"""
Performance Budget & Latency SLA Tests:
Ensures high-performance execution budgets are strictly satisfied:
1. Default Mine pattern endpoint executes in < 2.0 seconds.
2. Full statistical evaluation (Fisher + FDR + 1000 Permutations + 100 Bootstraps) executes in < 5.0 seconds.
"""
import time
import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


def test_mine_response_time_budget(client):
    """Ensures /api/mine completes within the strict 2.0-second SLA budget."""
    t0 = time.perf_counter()
    res = client.get("/api/mine?min_support=0.25&min_conf=0.7&min_lift=1.0&algorithm=apriori")
    elapsed = time.perf_counter() - t0

    assert res.status_code == 200
    assert elapsed < 2.0, f"Mine endpoint exceeded 2.0s SLA: took {elapsed:.3f}s"


def test_statistical_eval_response_time_budget(client):
    """Ensures /api/statistical_eval with default 1000 permutations completes within the 5.0-second SLA budget."""
    t0 = time.perf_counter()
    res = client.get("/api/statistical_eval?min_support=0.25&min_conf=0.7&n_bootstraps=100&n_permutations=1000&seed=42")
    elapsed = time.perf_counter() - t0

    assert res.status_code == 200
    assert elapsed < 5.0, f"Statistical evaluation exceeded 5.0s SLA: took {elapsed:.3f}s"
