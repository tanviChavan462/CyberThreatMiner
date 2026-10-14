"""
Bootstrap stability analysis for association rules.
Resamples threat group transactions 100+ times with replacement to determine
the empirical survival rate of each discovered rule.
Vectorised via matrix operations for sub-second execution on up to 500 rules.
"""
from typing import List, Set, Dict, FrozenSet, Tuple, Optional
import numpy as np
from backend.algorithms.rules import AssociationRule


def evaluate_bootstrap_stability(
    rules: List[AssociationRule],
    transactions: List[Set[str]],
    min_support: float,
    min_confidence: float,
    n_bootstraps: int = 100,
    random_seed: int = 42
) -> List[AssociationRule]:
    """
    Assesses rule stability by resampling transactions with replacement.

    Args:
        rules: List of discovered AssociationRule objects.
        transactions: List of transaction item sets.
        min_support: Minimum support threshold.
        min_confidence: Minimum confidence threshold.
        n_bootstraps: Number of bootstrap iterations (default: 100).
        random_seed: Reproducibility seed.

    Returns:
        Updated rules with `stability_pct` and `sig_boot` fields populated.
    """
    if not rules or not transactions:
        return rules

    n_tx = len(transactions)
    n_rules = len(rules)
    rng = np.random.default_rng(random_seed)

    # Precompute rule itemsets & boolean occurrence vectors across transactions
    # Shape: (n_rules, n_tx)
    mask_union = np.zeros((n_rules, n_tx), dtype=bool)
    mask_ante = np.zeros((n_rules, n_tx), dtype=bool)

    for r_idx, rule in enumerate(rules):
        union_set = rule.antecedent | rule.consequent
        ante_set = rule.antecedent
        for tx_idx, tx in enumerate(transactions):
            if union_set.issubset(tx):
                mask_union[r_idx, tx_idx] = True
            if ante_set.issubset(tx):
                mask_ante[r_idx, tx_idx] = True

    # Vectorized bootstrap resampling
    # Draw bootstrap transaction counts: (n_bootstraps, n_tx)
    sample_indices = rng.choice(n_tx, size=(n_bootstraps, n_tx), replace=True)
    weights = np.zeros((n_bootstraps, n_tx), dtype=np.int32)
    for b in range(n_bootstraps):
        weights[b, :] = np.bincount(sample_indices[b], minlength=n_tx)

    # Matrix multiplication: (n_bootstraps, n_tx) @ (n_tx, n_rules) -> (n_bootstraps, n_rules)
    counts_union = weights @ mask_union.T
    counts_ante = weights @ mask_ante.T

    # Sample supports & confidences
    sample_sup = counts_union / float(n_tx)
    with np.errstate(divide="ignore", invalid="ignore"):
        sample_conf = np.where(counts_ante > 0, counts_union / counts_ante, 0.0)

    # Determine survival per bootstrap replicate
    survives = (sample_sup >= min_support) & (sample_conf >= min_confidence)
    stabilities = (survives.mean(axis=0)) * 100.0

    for r_idx, rule in enumerate(rules):
        stab = float(round(stabilities[r_idx], 1))
        rule.stability_pct = stab
        rule.sig_boot = bool(stab >= 80.0)

    return rules
