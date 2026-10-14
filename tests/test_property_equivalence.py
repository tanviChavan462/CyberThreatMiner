"""
Property-based Equivalence Tests:
Verifies Apriori == FP-Growth == Eclat across multiple random synthetic datasets and seeds.
"""
import pytest
import numpy as np
from backend.algorithms.apriori import AprioriMiner
from backend.algorithms.fp_growth import FPGrowthMiner
from backend.algorithms.eclat import EclatMiner


@pytest.mark.parametrize("seed", [11, 42, 99, 123, 777])
def test_algorithms_equivalence_on_random_synthetic_data(seed):
    """Verifies that across different random transaction baskets, all three miners find identical itemsets and supports."""
    rng = np.random.default_rng(seed)
    n_tx = 120
    n_items = 35
    density = 0.12
    items = [f"TECH_{i:02d}" for i in range(n_items)]

    synthetic_tx = []
    for _ in range(n_tx):
        mask = rng.random(n_items) < density
        chosen = [items[i] for i in np.where(mask)[0]]
        if len(chosen) >= 2:
            synthetic_tx.append(set(chosen))
        else:
            synthetic_tx.append(set(rng.choice(items, size=2, replace=False)))

    min_sup = 0.10
    max_len = 3

    ap_miner = AprioriMiner()
    fp_miner = FPGrowthMiner()
    ec_miner = EclatMiner()

    ap_sets, _ = ap_miner.mine(synthetic_tx, min_support=min_sup, max_len=max_len)
    fp_sets = fp_miner.mine(synthetic_tx, min_support=min_sup, max_len=max_len)
    ec_sets = ec_miner.mine(synthetic_tx, min_support=min_sup, max_len=max_len)

    # 1. Exact identical set of frequent itemsets discovered
    assert set(ap_sets.keys()) == set(fp_sets.keys())
    assert set(ap_sets.keys()) == set(ec_sets.keys())

    # 2. Exact float support agreement
    for itemset, ap_sup in ap_sets.items():
        assert pytest.approx(ap_sup, abs=1e-6) == fp_sets[itemset]
        assert pytest.approx(ap_sup, abs=1e-6) == ec_sets[itemset]
