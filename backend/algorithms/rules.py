"""
Association Rule Generation and Advanced Evaluation Metrics.
Computes 10 interest measures:
1. Support
2. Confidence
3. Lift
4. Leverage
5. Conviction
6. Zhang's Metric
7. Jaccard Similarity
8. Kulczynski Measure
9. Cosine Measure
10. All-Confidence

Also provides:
- Redundant rule pruning
- Composite multi-objective ranking score
- Plain-English insight card generation
"""
from typing import Dict, FrozenSet, List, Tuple, Any, Optional, Set
import math
from itertools import combinations


class AssociationRule:
    """Represents an association rule A -> B with comprehensive metrics."""

    def __init__(
        self,
        antecedent: FrozenSet[str],
        consequent: FrozenSet[str],
        support: float,
        confidence: float,
        lift: float,
        leverage: float,
        conviction: float,
        zhang: float,
        jaccard: float,
        kulczynski: float,
        cosine: float,
        all_confidence: float,
        support_a: float,
        support_b: float
    ):
        self.antecedent = antecedent
        self.consequent = consequent
        self.support = round(support, 4)
        self.confidence = round(confidence, 4)
        self.lift = round(lift, 3)
        self.leverage = round(leverage, 4)
        self.conviction = round(conviction, 3) if not math.isinf(conviction) else 999.0
        self.zhang = round(zhang, 3)
        self.jaccard = round(jaccard, 3)
        self.kulczynski = round(kulczynski, 3)
        self.cosine = round(cosine, 3)
        self.all_confidence = round(all_confidence, 3)
        self.support_a = round(support_a, 4)
        self.support_b = round(support_b, 4)
        
        # Validation / Statistical fields (populated by statistical testing module)
        self.p_value: Optional[float] = None
        self.q_value: Optional[float] = None
        self.neg_log10_p: Optional[float] = None
        self.neg_log10_q: Optional[float] = None
        self.stability_pct: Optional[float] = None
        self.permutation_p_value: Optional[float] = None
        self.permutation_p_str: Optional[str] = None
        self.sig_fisher: bool = False
        self.sig_perm: bool = False
        self.sig_boot: bool = False
        self.is_significant: bool = False
        self.composite_score: float = 0.0

    def generate_plain_english(self, technique_names: Optional[Dict[str, Dict[str, Any]]] = None) -> str:
        """Generates clear, non-causal plain-English narrative for the rule."""
        def format_items(items: FrozenSet[str]) -> str:
            if technique_names:
                formatted = [f"{t} ({technique_names.get(t, {}).get('name', t)})" for t in sorted(items)]
                return ", ".join(formatted)
            return ", ".join(sorted(items))

        ante_str = format_items(self.antecedent)
        cons_str = format_items(self.consequent)
        conf_pct = f"{self.confidence * 100:.1f}%"
        lift_str = f"{self.lift:.1f}x"

        return (
            f"Threat groups observed utilizing [{ante_str}] also have [{cons_str}] "
            f"documented in {conf_pct} of threat dossiers ({lift_str} higher than baseline co-occurrence rate)."
        )

    def to_dict(self, technique_names: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
        """Serializes rule to JSON dictionary."""
        def label(t: str) -> str:
            if technique_names and t in technique_names:
                return f"{t} {technique_names[t]['name']}"
            return t

        return {
            "if": [label(t) for t in sorted(self.antecedent)],
            "then": [label(t) for t in sorted(self.consequent)],
            "raw_if": sorted(list(self.antecedent)),
            "raw_then": sorted(list(self.consequent)),
            "support": self.support,
            "confidence": self.confidence,
            "lift": self.lift,
            "leverage": self.leverage,
            "conviction": self.conviction,
            "zhang": self.zhang,
            "jaccard": self.jaccard,
            "kulczynski": self.kulczynski,
            "cosine": self.cosine,
            "all_confidence": self.all_confidence,
            "support_a": self.support_a,
            "support_b": self.support_b,
            "p_value": self.p_value,
            "q_value": self.q_value,
            "neg_log10_p": self.neg_log10_p,
            "neg_log10_q": self.neg_log10_q,
            "stability_pct": self.stability_pct,
            "permutation_p_value": self.permutation_p_value,
            "permutation_p_str": self.permutation_p_str,
            "sig_fisher": self.sig_fisher,
            "sig_perm": self.sig_perm,
            "sig_boot": self.sig_boot,
            "is_significant": self.is_significant,
            "composite_score": round(self.composite_score, 3),
            "plain_english": self.generate_plain_english(technique_names)
        }


def generate_rules(
    frequent_itemsets: Dict[FrozenSet[str], float],
    min_confidence: float = 0.5,
    min_lift: float = 1.0,
    prune_redundant: bool = False,
    top_k: Optional[int] = None,
    weights: Optional[Dict[str, float]] = None
) -> List[AssociationRule]:
    """
    Generates association rules from frequent itemsets satisfying confidence and lift thresholds.

    Args:
        frequent_itemsets: Dictionary of frequent itemsets and their support.
        min_confidence: Minimum rule confidence threshold.
        min_lift: Minimum rule lift threshold.
        prune_redundant: Whether to filter out non-minimal redundant rules.
        top_k: Optional maximum number of rules to return.
        weights: Dictionary of metric weights for composite ranking.
    """
    rules: List[AssociationRule] = []

    # Filter itemsets with at least 2 items
    multi_itemsets = [itemset for itemset in frequent_itemsets if len(itemset) >= 2]

    for itemset in multi_itemsets:
        sup_ab = frequent_itemsets[itemset]
        items = list(itemset)
        n = len(items)

        # Generate all non-empty proper subsets as antecedents
        for r in range(1, n):
            for ante_tuple in combinations(items, r):
                ante = frozenset(ante_tuple)
                cons = itemset - ante

                sup_a = frequent_itemsets.get(ante)
                sup_b = frequent_itemsets.get(cons)

                if sup_a is None or sup_b is None or sup_a == 0 or sup_b == 0:
                    continue

                conf = sup_ab / sup_a
                if conf < min_confidence:
                    continue

                lift = conf / sup_b
                if lift < min_lift:
                    continue

                # Extra measures
                leverage = sup_ab - (sup_a * sup_b)
                
                # Conviction
                if abs(1.0 - conf) < 1e-9:
                    conviction = float("inf")
                else:
                    conviction = (1.0 - sup_b) / (1.0 - conf)

                # Zhang's metric
                denom_zhang = max(conf * (1.0 - sup_b), sup_b * (1.0 - conf))
                zhang = (conf - sup_b) / denom_zhang if denom_zhang > 1e-9 else 0.0

                # Jaccard
                denom_jaccard = sup_a + sup_b - sup_ab
                jaccard = sup_ab / denom_jaccard if denom_jaccard > 1e-9 else 0.0

                # Kulczynski
                conf_ba = sup_ab / sup_b
                kulczynski = 0.5 * (conf + conf_ba)

                # Cosine
                cosine = sup_ab / math.sqrt(sup_a * sup_b)

                # All-confidence
                all_confidence = sup_ab / max(sup_a, sup_b)

                rule = AssociationRule(
                    antecedent=ante,
                    consequent=cons,
                    support=sup_ab,
                    confidence=conf,
                    lift=lift,
                    leverage=leverage,
                    conviction=conviction,
                    zhang=zhang,
                    jaccard=jaccard,
                    kulczynski=kulczynski,
                    cosine=cosine,
                    all_confidence=all_confidence,
                    support_a=sup_a,
                    support_b=sup_b
                )
                rules.append(rule)

    # Optional redundant rule pruning
    if prune_redundant:
        rules = prune_redundant_rules(rules)

    # Compute composite scores
    default_weights = {"lift": 0.35, "confidence": 0.35, "support": 0.15, "zhang": 0.15}
    w = weights if weights else default_weights

    # Normalize lift for composite score
    max_lift = max([r.lift for r in rules], default=1.0)
    for r in rules:
        norm_lift = min(1.0, r.lift / max(1.0, max_lift))
        norm_zhang = (r.zhang + 1.0) / 2.0  # map [-1, 1] to [0, 1]
        r.composite_score = (
            w.get("lift", 0.35) * norm_lift +
            w.get("confidence", 0.35) * r.confidence +
            w.get("support", 0.15) * r.support +
            w.get("zhang", 0.15) * norm_zhang
        )

    # Sort descending by composite score (fallback to lift and confidence)
    rules.sort(key=lambda x: (x.composite_score, x.lift, x.confidence), reverse=True)

    if top_k is not None and top_k > 0:
        return rules[:top_k]

    return rules


def prune_redundant_rules(rules: List[AssociationRule]) -> List[AssociationRule]:
    """
    Prunes redundant rules:
    A rule A' -> B' is redundant if there exists a simpler rule A -> B where
    A <= A', B <= B', and confidence(A -> B) >= confidence(A' -> B').
    """
    non_redundant: List[AssociationRule] = []
    
    # Sort by antecedent length ascending
    sorted_rules = sorted(rules, key=lambda r: (len(r.antecedent), len(r.consequent), -r.confidence))

    for candidate in sorted_rules:
        is_redundant = False
        for general in non_redundant:
            # Check if general is a strict sub-rule
            if (general.antecedent.issubset(candidate.antecedent) and
                general.consequent.issubset(candidate.consequent) and
                (general.antecedent != candidate.antecedent or general.consequent != candidate.consequent)):
                if general.confidence >= candidate.confidence:
                    is_redundant = True
                    break
        if not is_redundant:
            non_redundant.append(candidate)

    return non_redundant
