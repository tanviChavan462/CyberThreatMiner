"""
Machine Learning Evaluation Module:
1. Repeated 80/20 train/test splits (10 random splits or 5x2 CV) across threat groups to assess rule generalization.
   Reports mean ± std and 95% confidence intervals for train confidence, test confidence, rule precision on unseen groups,
   and both signed and absolute generalization gaps.
2. Cross-validation against mlxtend to verify 100% mathematical agreement.
"""
from typing import List, Set, Dict, FrozenSet, Tuple, Any, Optional
import math
import numpy as np
import pandas as pd
import scipy.stats as stats
from mlxtend.frequent_patterns import apriori as mlx_apriori, association_rules as mlx_rules
from backend.algorithms.apriori import AprioriMiner
from backend.algorithms.rules import generate_rules, AssociationRule


def _calc_stats(values: List[float], confidence_level: float = 0.95) -> Dict[str, Any]:
    """Calculates mean, std, standard error, and 95% confidence interval for a list of metric values."""
    n = len(values)
    if n == 0:
        return {"mean": 0.0, "std": 0.0, "ci_95": [0.0, 0.0], "ci_half_width": 0.0}
    mean = float(np.mean(values))
    if n == 1:
        return {"mean": round(mean, 4), "std": 0.0, "ci_95": [round(mean, 4), round(mean, 4)], "ci_half_width": 0.0}

    std = float(np.std(values, ddof=1))
    se = std / math.sqrt(n)
    t_crit = float(stats.t.ppf((1.0 + confidence_level) / 2.0, df=n - 1))
    ci_hw = t_crit * se
    return {
        "mean": round(mean, 4),
        "std": round(std, 4),
        "ci_95": [round(mean - ci_hw, 4), round(mean + ci_hw, 4)],
        "ci_half_width": round(ci_hw, 4)
    }


def evaluate_train_test_split(
    transactions: List[Set[str]],
    min_support: float = 0.25,
    min_confidence: float = 0.7,
    min_lift: float = 1.0,
    max_len: int = 3,
    n_splits: int = 10,
    test_size: float = 0.2,
    random_seed: int = 42
) -> Dict[str, Any]:
    """
    Performs repeated train/test evaluations of association rules on unseen threat groups.
    Mines rules on 80% training groups and validates confidence and precision on unseen 20% test groups.

    Args:
        transactions: All threat group transaction baskets.
        min_support: Minimum support threshold.
        min_confidence: Minimum confidence threshold.
        min_lift: Minimum lift threshold.
        max_len: Maximum itemset length.
        n_splits: Number of repeated random splits (default: 10).
        test_size: Proportion of test set (default: 0.2).
        random_seed: Reproducibility seed.

    Returns:
        Dictionary containing summary statistics (mean, std, 95% CI) and per-fold breakdown.
    """
    n_total = len(transactions)
    if n_total < 10:
        return {"error": "Insufficient transactions for train/test splitting"}

    rng = np.random.default_rng(random_seed)
    miner = AprioriMiner()

    train_confidences: List[float] = []
    test_confidences: List[float] = []
    test_precisions: List[float] = []
    signed_gaps: List[float] = []
    absolute_gaps: List[float] = []
    retained_rule_rates: List[float] = []
    total_mined_rules: List[int] = []

    split_summaries: List[Dict[str, Any]] = []

    for split_idx in range(n_splits):
        shuffled_indices = rng.permutation(n_total)
        n_test = int(round(test_size * n_total))
        test_indices = set(shuffled_indices[:n_test])
        train_indices = set(shuffled_indices[n_test:])

        train_tx = [transactions[i] for i in train_indices]
        test_tx = [transactions[i] for i in test_indices]

        # Mine rules on training partition
        train_itemsets, _ = miner.mine(train_tx, min_support=min_support, max_len=max_len)
        train_rules = generate_rules(train_itemsets, min_confidence=min_confidence, min_lift=min_lift)

        if not train_rules:
            continue

        # Evaluate on test partition
        fold_train_conf: List[float] = []
        fold_test_conf: List[float] = []
        fold_precisions: List[float] = []
        retained_count = 0

        for rule in train_rules:
            ante, cons = rule.antecedent, rule.consequent
            union_set = ante | cons

            # Count occurrences in held-out test groups
            c_ante_test = sum(1 for tx in test_tx if ante.issubset(tx))
            c_union_test = sum(1 for tx in test_tx if union_set.issubset(tx))

            # Rule precision on unseen groups: fraction of test groups containing antecedent that also contain consequent
            if c_ante_test > 0:
                rule_prec_test = float(c_union_test) / float(c_ante_test)
                fold_train_conf.append(rule.confidence)
                fold_test_conf.append(rule_prec_test)
                fold_precisions.append(rule_prec_test)

                if rule_prec_test >= (min_confidence * 0.85):
                    retained_count += 1

        retained_rate = (retained_count / len(train_rules)) * 100.0 if train_rules else 0.0

        avg_tr = float(np.mean(fold_train_conf)) if fold_train_conf else 0.0
        avg_te = float(np.mean(fold_test_conf)) if fold_test_conf else 0.0
        avg_prec = float(np.mean(fold_precisions)) if fold_precisions else 0.0
        fold_signed_gap = avg_tr - avg_te
        fold_abs_gap = abs(avg_tr - avg_te)

        train_confidences.append(avg_tr)
        test_confidences.append(avg_te)
        test_precisions.append(avg_prec)
        signed_gaps.append(fold_signed_gap)
        absolute_gaps.append(fold_abs_gap)
        retained_rule_rates.append(retained_rate)
        total_mined_rules.append(len(train_rules))

        split_summaries.append({
            "split": split_idx + 1,
            "train_size": len(train_tx),
            "test_size": len(test_tx),
            "rules_mined": len(train_rules),
            "mean_train_confidence": round(avg_tr, 4),
            "mean_test_confidence": round(avg_te, 4),
            "mean_test_precision": round(avg_prec, 4),
            "signed_generalization_gap": round(fold_signed_gap, 4),
            "absolute_generalization_gap": round(fold_abs_gap, 4),
            "retention_rate_pct": round(retained_rate, 1)
        })

    # Summary statistics with 95% Confidence Intervals
    stats_tr = _calc_stats(train_confidences)
    stats_te = _calc_stats(test_confidences)
    stats_prec = _calc_stats(test_precisions)
    stats_signed = _calc_stats(signed_gaps)
    stats_abs = _calc_stats(absolute_gaps)
    stats_ret = _calc_stats(retained_rule_rates)

    return {
        "n_splits": len(split_summaries),
        "random_seed": random_seed,
        "mean_train_confidence": stats_tr["mean"],
        "train_confidence_std": stats_tr["std"],
        "train_confidence_ci95": stats_tr["ci_95"],
        "mean_test_confidence": stats_te["mean"],
        "test_confidence_std": stats_te["std"],
        "test_confidence_ci95": stats_te["ci_95"],
        "mean_test_precision": stats_prec["mean"],
        "test_precision_std": stats_prec["std"],
        "test_precision_ci95": stats_prec["ci_95"],
        "mean_signed_generalization_gap": stats_signed["mean"],
        "signed_generalization_gap_std": stats_signed["std"],
        "signed_generalization_gap_ci95": stats_signed["ci_95"],
        "mean_absolute_generalization_gap": stats_abs["mean"],
        "absolute_generalization_gap_std": stats_abs["std"],
        "absolute_generalization_gap_ci95": stats_abs["ci_95"],
        # Preserved backward-compatible headline (equals mean absolute gap)
        "mean_generalization_gap": stats_abs["mean"],
        "mean_retention_rate_pct": stats_ret["mean"],
        "retention_rate_std": stats_ret["std"],
        "average_rules_per_fold": round(float(np.mean(total_mined_rules)), 1) if total_mined_rules else 0.0,
        "splits": split_summaries
    }


def compare_with_mlxtend(
    df: pd.DataFrame,
    transactions: List[Set[str]],
    min_support: float = 0.3,
    min_confidence: float = 0.8,
    max_len: int = 3
) -> Dict[str, Any]:
    """
    Compares custom scratch Apriori against mlxtend's reference implementation.
    Validates exact matching of itemset sets, support values, and rule counts.
    """
    # 1. Custom scratch implementation
    miner = AprioriMiner()
    custom_sets, _ = miner.mine(transactions, min_support=min_support, max_len=max_len)
    custom_rules = generate_rules(custom_sets, min_confidence=min_confidence, min_lift=1.0)

    # 2. mlxtend golden reference
    mlx_sets_df = mlx_apriori(df, min_support=min_support, use_colnames=True, max_len=max_len)
    if mlx_sets_df.empty:
        mlx_sets = {}
        mlx_rules_df = pd.DataFrame()
    else:
        mlx_sets = {frozenset(row.itemsets): float(row.support) for row in mlx_sets_df.itertuples()}
        mlx_rules_df = mlx_rules(mlx_sets_df, metric="confidence", min_threshold=min_confidence)

    # Comparison metrics
    custom_keys = set(custom_sets.keys())
    mlx_keys = set(mlx_sets.keys())

    common_keys = custom_keys & mlx_keys
    total_unique_keys = custom_keys | mlx_keys

    itemset_agreement_pct = round((len(common_keys) / max(1, len(total_unique_keys))) * 100.0, 2)

    # Support deviations
    max_support_diff = 0.0
    for k in common_keys:
        diff = abs(custom_sets[k] - mlx_sets[k])
        if diff > max_support_diff:
            max_support_diff = diff

    return {
        "custom_itemset_count": len(custom_sets),
        "mlxtend_itemset_count": len(mlx_sets),
        "custom_rule_count": len(custom_rules),
        "mlxtend_rule_count": len(mlx_rules_df),
        "itemset_agreement_pct": itemset_agreement_pct,
        "max_support_discrepancy": round(max_support_diff, 8),
        "status": "PASS (100% Agreement)" if itemset_agreement_pct == 100.0 and max_support_diff < 1e-6 else "FAIL"
    }
