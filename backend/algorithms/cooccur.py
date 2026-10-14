"""
Co-occurring Techniques Analysis & Threat Group Fingerprinting.
Strictly non-predictive, non-causal observational association intelligence.
"""
from typing import Dict, List, Set, FrozenSet, Any, Optional
from backend.algorithms.rules import AssociationRule


NON_CAUSAL_DISCLAIMER = (
    "DISCLAIMER: Discovered technique co-occurrences reflect statistical correlations in historical "
    "adversary dossiers documented by MITRE ATT&CK. They DO NOT indicate chronological attack sequences, "
    "causal prerequisites, or predictive forecasts of future adversary behavior."
)


def find_cooccurring_techniques(
    seen_techniques: List[str],
    rules: List[AssociationRule],
    technique_info: Dict[str, Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Identifies techniques statistically associated with a given set of observed techniques.

    Args:
        seen_techniques: List of techniques already observed.
        rules: Pre-mined association rules.
        technique_info: Technique metadata dictionary.

    Returns:
        Dictionary with ranked co-occurring techniques and domain disclaimer.
    """
    seen_set = set(seen_techniques)
    best_matches: Dict[str, Dict[str, Any]] = {}

    for rule in rules:
        if rule.antecedent.issubset(seen_set):
            for t in rule.consequent:
                if t not in seen_set:
                    # Update if not seen or if current rule offers higher confidence
                    if t not in best_matches or rule.confidence > best_matches[t]["confidence"]:
                        t_name = technique_info.get(t, {}).get("name", t)
                        best_matches[t] = {
                            "id": t,
                            "label": f"{t} {t_name}",
                            "confidence": rule.confidence,
                            "lift": rule.lift,
                            "support": rule.support,
                            "trigger_antecedent": [f"{a} {technique_info.get(a, {}).get('name', a)}" for a in sorted(rule.antecedent)],
                            "rule_p_value": rule.p_value,
                            "plain_english": (
                                f"Historical groups that used {', '.join(rule.antecedent)} "
                                f"also documented {t} in {rule.confidence * 100:.1f}% of cases ({rule.lift:.1f}x baseline expectation)."
                            )
                        }

    # Rank by confidence descending, then lift
    ranked = sorted(best_matches.values(), key=lambda x: (x["confidence"], x["lift"]), reverse=True)[:15]

    return {
        "query_techniques": [f"{t} {technique_info.get(t, {}).get('name', t)}" for t in sorted(seen_set)],
        "cooccurring_techniques": ranked,
        "disclaimer": NON_CAUSAL_DISCLAIMER
    }


def compute_group_fingerprint(
    group_name: str,
    transactions: Dict[str, List[str]],
    technique_info: Dict[str, Dict[str, Any]],
    rules: List[AssociationRule]
) -> Dict[str, Any]:
    """
    Computes a forensic fingerprint for a threat group:
    - Technique basket & tactic distribution
    - Most similar peer groups via Jaccard similarity
    - Applicable association rules covered by this group
    """
    if group_name not in transactions:
        return {"error": f"Group '{group_name}' not found in dataset"}

    group_techs = set(transactions[group_name])

    # Tactic distribution
    tactic_counts: Dict[str, int] = {}
    for t in group_techs:
        tactics = technique_info.get(t, {}).get("tactics", [])
        for tac in tactics:
            tactic_counts[tac] = tactic_counts.get(tac, 0) + 1

    # Find similar peer groups
    similarities = []
    for other_group, other_techs_list in transactions.items():
        if other_group == group_name:
            continue
        other_techs = set(other_techs_list)
        intersection = group_techs & other_techs
        union = group_techs | other_techs
        jaccard = len(intersection) / max(1, len(union))
        if jaccard > 0:
            similarities.append({
                "group": other_group,
                "jaccard_similarity": round(jaccard, 3),
                "shared_techniques_count": len(intersection),
                "total_techniques": len(other_techs),
                "shared_sample": sorted(list(intersection))[:5]
            })

    similarities.sort(key=lambda x: x["jaccard_similarity"], reverse=True)

    # Covered rules (both antecedent and consequent exist in group's techniques)
    covered_rules = []
    for r in rules:
        if (r.antecedent | r.consequent).issubset(group_techs):
            covered_rules.append(r.to_dict(technique_info))

    return {
        "group": group_name,
        "technique_count": len(group_techs),
        "techniques": [f"{t} {technique_info.get(t, {}).get('name', t)}" for t in sorted(group_techs)],
        "tactic_distribution": tactic_counts,
        "similar_groups": similarities[:8],
        "covered_rules_count": len(covered_rules),
        "covered_rules_sample": covered_rules[:6],
        "disclaimer": NON_CAUSAL_DISCLAIMER
    }
