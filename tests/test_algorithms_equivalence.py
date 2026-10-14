"""
Algorithmic Equivalence Tests:
Verifies that Apriori, FP-Growth, Eclat, and mlxtend all produce
100% identical frequent itemsets and identical support values.
"""
import pytest
import pandas as pd
from mlxtend.frequent_patterns import apriori as mlx_apriori
from backend.algorithms.apriori import AprioriMiner
from backend.algorithms.fp_growth import FPGrowthMiner
from backend.algorithms.eclat import EclatMiner


@pytest.fixture
def sample_dataset():
    transactions = [
        {"T1059", "T1082", "T1083", "T1005"},
        {"T1059", "T1082", "T1027"},
        {"T1059", "T1083", "T1005", "T1027"},
        {"T1082", "T1083", "T1005"},
        {"T1059", "T1082", "T1083", "T1027"},
        {"T1059", "T1005", "T1027"},
        {"T1082", "T1083", "T1027"},
        {"T1059", "T1082", "T1083", "T1005", "T1027"},
    ]
    return transactions


def test_three_algorithms_equivalence(sample_dataset):
    """Asserts Apriori == FP-Growth == Eclat."""
    ap_miner = AprioriMiner()
    fp_miner = FPGrowthMiner()
    ec_miner = EclatMiner()

    min_sup = 0.35
    max_len = 3

    ap_sets, _ = ap_miner.mine(sample_dataset, min_support=min_sup, max_len=max_len)
    fp_sets = fp_miner.mine(sample_dataset, min_support=min_sup, max_len=max_len)
    ec_sets = ec_miner.mine(sample_dataset, min_support=min_sup, max_len=max_len)

    # Identical itemsets discovered
    assert set(ap_sets.keys()) == set(fp_sets.keys())
    assert set(ap_sets.keys()) == set(ec_sets.keys())

    # Identical support floats
    for itemset in ap_sets:
        assert pytest.approx(ap_sets[itemset]) == fp_sets[itemset]
        assert pytest.approx(ap_sets[itemset]) == ec_sets[itemset]


def test_custom_apriori_vs_mlxtend(sample_dataset):
    """Asserts scratch Apriori matches mlxtend golden reference."""
    # Convert to one-hot DataFrame for mlxtend
    all_techs = sorted(list({t for tx in sample_dataset for t in tx}))
    df = pd.DataFrame(
        [[t in tx for t in all_techs] for tx in sample_dataset],
        columns=all_techs
    )

    min_sup = 0.35
    max_len = 3

    # Custom scratch Apriori
    ap_miner = AprioriMiner()
    custom_sets, _ = ap_miner.mine(sample_dataset, min_support=min_sup, max_len=max_len)

    # mlxtend reference
    mlx_df = mlx_apriori(df, min_support=min_sup, use_colnames=True, max_len=max_len)
    mlx_sets = {frozenset(row.itemsets): float(row.support) for row in mlx_df.itertuples()}

    assert set(custom_sets.keys()) == set(mlx_sets.keys())
    for itemset in custom_sets:
        assert pytest.approx(custom_sets[itemset]) == mlx_sets[itemset]
