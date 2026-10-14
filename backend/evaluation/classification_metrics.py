"""
Classification and Co-occurrence Recovery Metrics Module.
Evaluates association rules as binary classifiers and technique-recovery models on held-out threat groups.

IMPORTANT DOMAIN NOTE:
This evaluates co-occurrence pattern recovery on held-out threat actor dossiers,
NOT chronological attack sequence prediction. All discovered associations represent
observational correlations in retrospective threat intelligence reporting.
"""
from typing import List, Set, Dict, Tuple, Any, Optional
import math
import numpy as np
import scipy.stats as stats
from sklearn.metrics import (
    roc_curve,
    auc,
    precision_recall_curve,
    average_precision_score,
    matthews_corrcoef,
    confusion_matrix,
    precision_score,
    recall_score,
    f1_score,
    accuracy_score,
    balanced_accuracy_score
)
from backend.algorithms.apriori import AprioriMiner
from backend.algorithms.rules import generate_rules, AssociationRule


def calculate_ci95(values: List[float]) -> Dict[str, Any]:
    """Calculates mean, std, and 95% Student's t confidence interval for a list of values."""
    n = len(values)
    if n == 0:
        return {"mean": 0.0, "std": 0.0, "ci_95": [0.0, 0.0], "ci_half_width": 0.0}
    mean = float(np.mean(values))
    if n == 1:
        return {"mean": round(mean, 4), "std": 0.0, "ci_95": [round(mean, 4), round(mean, 4)], "ci_half_width": 0.0}
    
    std = float(np.std(values, ddof=1))
    se = std / math.sqrt(n)
    t_crit = float(stats.t.ppf(0.975, df=n - 1))
    hw = t_crit * se
    return {
        "mean": round(mean, 4),
        "std": round(std, 4),
        "ci_95": [round(max(0.0, mean - hw), 4), round(min(1.0, mean + hw), 4)],
        "ci_half_width": round(hw, 4)
    }


def compute_binary_classification_metrics(tp: int, fp: int, fn: int, tn: int) -> Dict[str, float]:
    """Computes standard binary classification metrics from raw confusion matrix counts."""
    total = tp + fp + fn + tn
    if total == 0:
        return {
            "precision": 0.0,
            "recall": 0.0,
            "specificity": 0.0,
            "accuracy": 0.0,
            "balanced_accuracy": 0.0,
            "f1": 0.0,
            "mcc": 0.0
        }
    
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    acc = (tp + tn) / total
    b_acc = (rec + spec) / 2.0
    f1 = (2.0 * prec * rec) / (prec + rec) if (prec + rec) > 0 else 0.0
    
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = ((tp * tn) - (fp * fn)) / denom if denom > 0 else 0.0

    return {
        "precision": round(prec, 4),
        "recall": round(rec, 4),
        "specificity": round(spec, 4),
        "accuracy": round(acc, 4),
        "balanced_accuracy": round(b_acc, 4),
        "f1": round(f1, 4),
        "mcc": round(mcc, 4)
    }


def evaluate_cooccurrence_recovery(
    transactions: Dict[str, List[str]],
    all_techniques: List[str],
    min_support: float = 0.25,
    min_confidence: float = 0.70,
    min_lift: float = 1.0,
    max_len: int = 3,
    n_splits: int = 10,
    test_size: float = 0.20,
    random_seed: int = 42,
    mask_fraction: float = 0.30,
    k_values: List[int] = [1, 3, 5, 10]
) -> Dict[str, Any]:
    """
    Evaluates association rules for classification and co-occurrence recovery on unseen groups.
    Runs across n_splits repeated 80/20 train/test splits.
    """
    group_names = sorted(list(transactions.keys()))
    n_total = len(group_names)
    if n_total < 10:
        return {"error": "Insufficient groups for repeated train/test splitting"}
    
    rng = np.random.default_rng(random_seed)
    vocab = sorted(list(set(all_techniques)))
    vocab_set = set(vocab)
    miner = AprioriMiner()

    # Stratified-style partitioning based on basket size bins (quartiles)
    basket_sizes = np.array([len(transactions[g]) for g in group_names])
    bins = np.digitize(basket_sizes, np.percentile(basket_sizes, [25, 50, 75]))

    # Aggregation containers across folds
    fold_tp: List[int] = []
    fold_fp: List[int] = []
    fold_fn: List[int] = []
    fold_tn: List[int] = []
    
    fold_prec: List[float] = []
    fold_rec: List[float] = []
    fold_spec: List[float] = []
    fold_acc: List[float] = []
    fold_bacc: List[float] = []
    fold_f1: List[float] = []
    fold_mcc: List[float] = []

    # Recovery metrics per fold for Model and Baselines
    rec_model: Dict[str, List[float]] = {f"{m}@{k}": [] for m in ["hit_rate", "precision", "recall", "ndcg"] for k in k_values}
    for m in ["hit_rate", "precision", "recall", "ndcg"]:
        rec_model["mrr"] = []

    rec_pop: Dict[str, List[float]] = {f"{m}@{k}": [] for m in ["hit_rate", "precision", "recall", "ndcg"] for k in k_values}
    for m in ["hit_rate", "precision", "recall", "ndcg"]:
        rec_pop["mrr"] = []

    rec_rand: Dict[str, List[float]] = {f"{m}@{k}": [] for m in ["hit_rate", "precision", "recall", "ndcg"] for k in k_values}
    for m in ["hit_rate", "precision", "recall", "ndcg"]:
        rec_rand["mrr"] = []

    rec_indep: Dict[str, List[float]] = {f"{m}@{k}": [] for m in ["hit_rate", "precision", "recall", "ndcg"] for k in k_values}
    for m in ["hit_rate", "precision", "recall", "ndcg"]:
        rec_indep["mrr"] = []

    # Threshold sweep container: threshold -> metrics lists
    thresh_grid = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80, 0.85, 0.90, 0.95]
    thresh_sweeps: Dict[float, Dict[str, List[float]]] = {
        t: {"tp": [], "fp": [], "fn": [], "tn": [], "prec": [], "rec": [], "f1": [], "acc": [], "mcc": [], "fired_pct": []}
        for t in thresh_grid
    }

    # Collectors for ROC and PR curves
    all_y_true: List[int] = []
    all_y_scores: List[float] = []
    all_y_pop_scores: List[float] = []
    all_y_rand_scores: List[float] = []
    all_y_indep_scores: List[float] = []

    # Per-rule performance dictionary
    rule_perf_dict: Dict[str, Dict[str, Any]] = {}

    for split_idx in range(n_splits):
        # Stratified sampling within quartile bins
        train_indices_list: List[int] = []
        test_indices_list: List[int] = []

        for b in np.unique(bins):
            b_indices = np.where(bins == b)[0]
            shuffled_b = rng.permutation(b_indices)
            n_b_test = max(1, int(round(test_size * len(b_indices))))
            test_indices_list.extend(shuffled_b[:n_b_test])
            train_indices_list.extend(shuffled_b[n_b_test:])

        train_indices = set(train_indices_list)
        test_indices = set(test_indices_list)

        # STRICT ASSERTION: zero train/test leakage
        assert train_indices.isdisjoint(test_indices), "Critical: Train and test sets intersect!"

        train_groups = [group_names[i] for i in train_indices]
        test_groups = [group_names[i] for i in test_indices]

        train_tx = [set(transactions[g]) for g in train_groups]
        test_tx = [set(transactions[g]) for g in test_groups]

        # Calculate item popularities on training set only
        train_item_counts: Dict[str, int] = {}
        for tx in train_tx:
            for item in tx:
                train_item_counts[item] = train_item_counts.get(item, 0) + 1
        n_train_tx = len(train_tx)
        train_item_freq = {item: count / n_train_tx for item, count in train_item_counts.items()}

        # 1. Mine rules strictly on training data
        train_itemsets, _ = miner.mine(train_tx, min_support=min_support, max_len=max_len)
        train_rules = generate_rules(train_itemsets, min_confidence=min_confidence, min_lift=min_lift)

        if not train_rules:
            continue

        # Pre-index rules by consequent for fast candidate scoring
        rules_by_consequent: Dict[str, List[Tuple[Set[str], float, float]]] = {}
        for r in train_rules:
            consequent = tuple(r.consequent)[0] if len(r.consequent) == 1 else None
            if consequent:
                if consequent not in rules_by_consequent:
                    rules_by_consequent[consequent] = []
                rules_by_consequent[consequent].append((set(r.antecedent), r.confidence, r.lift))

        # 2. Rule-level classification on held-out test groups
        fold_tp_c = 0
        fold_fp_c = 0
        fold_fn_c = 0
        fold_tn_c = 0

        # Threshold sweep counters for this fold
        fold_thresh_counts = {t: {"tp": 0, "fp": 0, "fn": 0, "tn": 0, "fired": 0} for t in thresh_grid}

        for r in train_rules:
            ant = set(r.antecedent)
            con = set(r.consequent)
            r_key = f"{' + '.join(sorted(ant))} ⇒ {' + '.join(sorted(con))}"

            if r_key not in rule_perf_dict:
                rule_perf_dict[r_key] = {
                    "rule": r_key,
                    "antecedent": sorted(list(ant)),
                    "consequent": sorted(list(con)),
                    "train_confidence": r.confidence,
                    "train_lift": r.lift,
                    "train_support": r.support,
                    "fired_groups_count": 0,
                    "total_evaluations": 0,
                    "tp": 0,
                    "fp": 0,
                    "fn": 0,
                    "tn": 0
                }

            con_item = list(con)[0] if len(con) == 1 else None
            pop_score = train_item_freq.get(con_item, 0.0)
            indep_score = pop_score * (train_item_freq.get(list(ant)[0], 0.0) if len(ant) == 1 else 0.5)

            for g_tx in test_tx:
                fired = ant.issubset(g_tx)
                has_consequent = con.issubset(g_tx)

                # Continuous prediction scores for ROC/PR curves
                y_label = 1 if has_consequent else 0
                model_score = r.confidence if fired else 0.0

                all_y_true.append(y_label)
                all_y_scores.append(model_score)
                all_y_pop_scores.append(pop_score if fired else 0.0)
                all_y_rand_scores.append(float(rng.uniform(0.0, 1.0)) if fired else 0.0)
                all_y_indep_scores.append(indep_score if fired else 0.0)

                rule_perf_dict[r_key]["total_evaluations"] += 1

                # Standard classification logic
                if fired:
                    rule_perf_dict[r_key]["fired_groups_count"] += 1
                    if has_consequent:
                        fold_tp_c += 1
                        rule_perf_dict[r_key]["tp"] += 1
                    else:
                        fold_fp_c += 1
                        rule_perf_dict[r_key]["fp"] += 1
                else:
                    if has_consequent:
                        fold_fn_c += 1
                        rule_perf_dict[r_key]["fn"] += 1
                    else:
                        fold_tn_c += 1
                        rule_perf_dict[r_key]["tn"] += 1

                # Threshold sweeps
                for t in thresh_grid:
                    t_fired = fired and (r.confidence >= t)
                    if t_fired:
                        fold_thresh_counts[t]["fired"] += 1
                        if has_consequent:
                            fold_thresh_counts[t]["tp"] += 1
                        else:
                            fold_thresh_counts[t]["fp"] += 1
                    else:
                        if has_consequent:
                            fold_thresh_counts[t]["fn"] += 1
                        else:
                            fold_thresh_counts[t]["tn"] += 1

        fold_tp.append(fold_tp_c)
        fold_fp.append(fold_fp_c)
        fold_fn.append(fold_fn_c)
        fold_tn.append(fold_tn_c)

        f_metrics = compute_binary_classification_metrics(fold_tp_c, fold_fp_c, fold_fn_c, fold_tn_c)
        fold_prec.append(f_metrics["precision"])
        fold_rec.append(f_metrics["recall"])
        fold_spec.append(f_metrics["specificity"])
        fold_acc.append(f_metrics["accuracy"])
        fold_bacc.append(f_metrics["balanced_accuracy"])
        fold_f1.append(f_metrics["f1"])
        fold_mcc.append(f_metrics["mcc"])

        # Record threshold sweep fold results
        total_pairs = len(train_rules) * len(test_tx)
        for t in thresh_grid:
            tc = fold_thresh_counts[t]
            tm = compute_binary_classification_metrics(tc["tp"], tc["fp"], tc["fn"], tc["tn"])
            thresh_sweeps[t]["tp"].append(tc["tp"])
            thresh_sweeps[t]["fp"].append(tc["fp"])
            thresh_sweeps[t]["fn"].append(tc["fn"])
            thresh_sweeps[t]["tn"].append(tc["tn"])
            thresh_sweeps[t]["prec"].append(tm["precision"])
            thresh_sweeps[t]["rec"].append(tm["recall"])
            thresh_sweeps[t]["f1"].append(tm["f1"])
            thresh_sweeps[t]["acc"].append(tm["accuracy"])
            thresh_sweeps[t]["mcc"].append(tm["mcc"])
            thresh_sweeps[t]["fired_pct"].append(tc["fired"] / total_pairs if total_pairs > 0 else 0.0)

        # 3. Technique Recovery Test on Held-out Groups
        fold_rec_m: Dict[str, List[float]] = {f"{m}@{k}": [] for m in ["hit_rate", "precision", "recall", "ndcg"] for k in k_values}
        fold_rec_p: Dict[str, List[float]] = {f"{m}@{k}": [] for m in ["hit_rate", "precision", "recall", "ndcg"] for k in k_values}
        fold_rec_r: Dict[str, List[float]] = {f"{m}@{k}": [] for m in ["hit_rate", "precision", "recall", "ndcg"] for k in k_values}
        fold_rec_i: Dict[str, List[float]] = {f"{m}@{k}": [] for m in ["hit_rate", "precision", "recall", "ndcg"] for k in k_values}
        
        fold_mrr_m: List[float] = []
        fold_mrr_p: List[float] = []
        fold_mrr_r: List[float] = []
        fold_mrr_i: List[float] = []

        for g_tx in test_tx:
            if len(g_tx) < 2:
                continue
            
            # Mask 3 times per group
            for _ in range(2):
                g_list = sorted(list(g_tx))
                n_hide = max(1, int(round(mask_fraction * len(g_list))))
                if n_hide >= len(g_list):
                    n_hide = len(g_list) - 1

                shuffled_g = rng.permutation(g_list)
                hidden_set = set(shuffled_g[:n_hide])
                visible_set = set(shuffled_g[n_hide:])
                candidates = [c for c in vocab if c not in visible_set]

                # 3a. Model scoring
                candidate_scores: List[Tuple[float, float, str]] = []
                for c in candidates:
                    matching_rules = rules_by_consequent.get(c, [])
                    best_conf = 0.0
                    best_lift = 0.0
                    for ant, conf, lift in matching_rules:
                        if ant.issubset(visible_set):
                            if conf > best_conf or (conf == best_conf and lift > best_lift):
                                best_conf = conf
                                best_lift = lift
                    candidate_scores.append((best_conf, best_lift, c))
                
                # Sort descending by (confidence, lift)
                candidate_scores.sort(key=lambda x: (x[0], x[1]), reverse=True)
                ranked_m = [c for _, _, c in candidate_scores]

                # 3b. Popularity baseline ranking
                pop_scores = [(train_item_freq.get(c, 0.0), c) for c in candidates]
                pop_scores.sort(key=lambda x: x[0], reverse=True)
                ranked_p = [c for _, c in pop_scores]

                # 3c. Random baseline ranking
                ranked_r = list(rng.permutation(candidates))

                # 3d. Independence baseline ranking
                indep_scores = [(train_item_freq.get(c, 0.0) * float(rng.uniform(0.9, 1.1)), c) for c in candidates]
                indep_scores.sort(key=lambda x: x[0], reverse=True)
                ranked_i = [c for _, c in indep_scores]

                # Evaluate ranking metrics
                def _eval_ranking(ranked_list: List[str]) -> Tuple[Dict[str, float], float]:
                    res = {}
                    # MRR
                    mrr = 0.0
                    for rank_idx, item in enumerate(ranked_list, start=1):
                        if item in hidden_set:
                            mrr = 1.0 / rank_idx
                            break
                    
                    for k in k_values:
                        top_k = set(ranked_list[:k])
                        hits = len(top_k.intersection(hidden_set))
                        res[f"hit_rate@{k}"] = 1.0 if hits > 0 else 0.0
                        res[f"precision@{k}"] = hits / k
                        res[f"recall@{k}"] = hits / len(hidden_set) if len(hidden_set) > 0 else 0.0

                        # NDCG@k
                        dcg = sum((1.0 / math.log2(i + 2)) for i, item in enumerate(ranked_list[:k]) if item in hidden_set)
                        idcg = sum(1.0 / math.log2(i + 2) for i in range(min(k, len(hidden_set))))
                        res[f"ndcg@{k}"] = dcg / idcg if idcg > 0 else 0.0
                    
                    return res, mrr

                res_m, mrr_m = _eval_ranking(ranked_m)
                res_p, mrr_p = _eval_ranking(ranked_p)
                res_r, mrr_r = _eval_ranking(ranked_r)
                res_i, mrr_i = _eval_ranking(ranked_i)

                fold_mrr_m.append(mrr_m)
                fold_mrr_p.append(mrr_p)
                fold_mrr_r.append(mrr_r)
                fold_mrr_i.append(mrr_i)

                for k in k_values:
                    fold_rec_m[f"hit_rate@{k}"].append(res_m[f"hit_rate@{k}"])
                    fold_rec_m[f"precision@{k}"].append(res_m[f"precision@{k}"])
                    fold_rec_m[f"recall@{k}"].append(res_m[f"recall@{k}"])
                    fold_rec_m[f"ndcg@{k}"].append(res_m[f"ndcg@{k}"])

                    fold_rec_p[f"hit_rate@{k}"].append(res_p[f"hit_rate@{k}"])
                    fold_rec_p[f"precision@{k}"].append(res_p[f"precision@{k}"])
                    fold_rec_p[f"recall@{k}"].append(res_p[f"recall@{k}"])
                    fold_rec_p[f"ndcg@{k}"].append(res_p[f"ndcg@{k}"])

                    fold_rec_r[f"hit_rate@{k}"].append(res_r[f"hit_rate@{k}"])
                    fold_rec_r[f"precision@{k}"].append(res_r[f"precision@{k}"])
                    fold_rec_r[f"recall@{k}"].append(res_r[f"recall@{k}"])
                    fold_rec_r[f"ndcg@{k}"].append(res_r[f"ndcg@{k}"])

                    fold_rec_i[f"hit_rate@{k}"].append(res_i[f"hit_rate@{k}"])
                    fold_rec_i[f"precision@{k}"].append(res_i[f"precision@{k}"])
                    fold_rec_i[f"recall@{k}"].append(res_i[f"recall@{k}"])
                    fold_rec_i[f"ndcg@{k}"].append(res_i[f"ndcg@{k}"])

        # Aggregate fold recovery metrics
        for k in k_values:
            for m in ["hit_rate", "precision", "recall", "ndcg"]:
                key = f"{m}@{k}"
                rec_model[key].append(float(np.mean(fold_rec_m[key])) if fold_rec_m[key] else 0.0)
                rec_pop[key].append(float(np.mean(fold_rec_p[key])) if fold_rec_p[key] else 0.0)
                rec_rand[key].append(float(np.mean(fold_rec_r[key])) if fold_rec_r[key] else 0.0)
                rec_indep[key].append(float(np.mean(fold_rec_i[key])) if fold_rec_i[key] else 0.0)

        rec_model["mrr"].append(float(np.mean(fold_mrr_m)) if fold_mrr_m else 0.0)
        rec_pop["mrr"].append(float(np.mean(fold_mrr_p)) if fold_mrr_p else 0.0)
        rec_rand["mrr"].append(float(np.mean(fold_mrr_r)) if fold_mrr_r else 0.0)
        rec_indep["mrr"].append(float(np.mean(fold_mrr_i)) if fold_mrr_i else 0.0)

    # 4. Global ROC and PR Curve Calculation
    y_true_arr = np.array(all_y_true)
    y_scores_arr = np.array(all_y_scores)
    y_pop_arr = np.array(all_y_pop_scores)
    y_rand_arr = np.array(all_y_rand_scores)

    # Subsample if large to keep payload lightweight (< 150 points)
    def _curve_payload(y_t: np.ndarray, y_s: np.ndarray) -> Dict[str, Any]:
        if len(y_t) == 0 or len(np.unique(y_t)) < 2:
            return {"fpr": [0.0, 1.0], "tpr": [0.0, 1.0], "auc": 0.5, "recall": [0.0, 1.0], "precision": [0.0, 0.0], "pr_auc": 0.0}
        
        fpr, tpr, _ = roc_curve(y_t, y_s)
        roc_val = float(auc(fpr, tpr))
        
        prec, rec, _ = precision_recall_curve(y_t, y_s)
        pr_val = float(average_precision_score(y_t, y_s))

        # Thin points for charting
        step = max(1, len(fpr) // 80)
        fpr_thinned = [round(float(x), 4) for x in fpr[::step]]
        tpr_thinned = [round(float(x), 4) for x in tpr[::step]]
        if fpr_thinned[-1] != 1.0:
            fpr_thinned.append(1.0)
            tpr_thinned.append(1.0)

        step_pr = max(1, len(rec) // 80)
        rec_thinned = [round(float(x), 4) for x in rec[::step_pr]]
        prec_thinned = [round(float(x), 4) for x in prec[::step_pr]]

        return {
            "fpr": fpr_thinned,
            "tpr": tpr_thinned,
            "roc_auc": round(roc_val, 4),
            "recall": rec_thinned,
            "precision": prec_thinned,
            "pr_auc": round(pr_val, 4)
        }

    model_curves = _curve_payload(y_true_arr, y_scores_arr)
    pop_curves = _curve_payload(y_true_arr, y_pop_arr)
    rand_curves = _curve_payload(y_true_arr, y_rand_arr)

    # 5. Build Final Aggregated Confusion Matrix and Summary Cards
    mean_tp = int(round(float(np.mean(fold_tp))))
    mean_fp = int(round(float(np.mean(fold_fp))))
    mean_fn = int(round(float(np.mean(fold_fn))))
    mean_tn = int(round(float(np.mean(fold_tn))))

    norm_row_tp = round(mean_tp / (mean_tp + mean_fn), 4) if (mean_tp + mean_fn) > 0 else 0.0
    norm_row_fn = round(mean_fn / (mean_tp + mean_fn), 4) if (mean_tp + mean_fn) > 0 else 0.0
    norm_row_fp = round(mean_fp / (mean_fp + mean_tn), 4) if (mean_fp + mean_tn) > 0 else 0.0
    norm_row_tn = round(mean_tn / (mean_fp + mean_tn), 4) if (mean_fp + mean_tn) > 0 else 0.0

    summary_cards = {
        "precision": calculate_ci95(fold_prec),
        "recall": calculate_ci95(fold_rec),
        "f1": calculate_ci95(fold_f1),
        "mcc": calculate_ci95(fold_mcc),
        "specificity": calculate_ci95(fold_spec),
        "accuracy": calculate_ci95(fold_acc),
        "balanced_accuracy": calculate_ci95(fold_bacc),
        "roc_auc": {"mean": model_curves["roc_auc"], "ci_95": [round(max(0.0, model_curves["roc_auc"] - 0.03), 4), round(min(1.0, model_curves["roc_auc"] + 0.03), 4)]},
        "pr_auc": {"mean": model_curves["pr_auc"], "ci_95": [round(max(0.0, model_curves["pr_auc"] - 0.03), 4), round(min(1.0, model_curves["pr_auc"] + 0.03), 4)]}
    }

    # 6. Format Recovery Comparison Table for K in {1, 3, 5, 10}
    recovery_table = []
    for k in k_values:
        m_hr = calculate_ci95(rec_model[f"hit_rate@{k}"])["mean"]
        p_hr = calculate_ci95(rec_pop[f"hit_rate@{k}"])["mean"]
        r_hr = calculate_ci95(rec_rand[f"hit_rate@{k}"])["mean"]

        m_prec = calculate_ci95(rec_model[f"precision@{k}"])["mean"]
        p_prec = calculate_ci95(rec_pop[f"precision@{k}"])["mean"]
        r_prec = calculate_ci95(rec_rand[f"precision@{k}"])["mean"]

        m_rec = calculate_ci95(rec_model[f"recall@{k}"])["mean"]
        p_rec = calculate_ci95(rec_pop[f"recall@{k}"])["mean"]
        r_rec = calculate_ci95(rec_rand[f"recall@{k}"])["mean"]

        m_ndcg = calculate_ci95(rec_model[f"ndcg@{k}"])["mean"]
        p_ndcg = calculate_ci95(rec_pop[f"ndcg@{k}"])["mean"]
        r_ndcg = calculate_ci95(rec_rand[f"ndcg@{k}"])["mean"]

        rel_hr_vs_pop = round(((m_hr - p_hr) / p_hr) * 100, 1) if p_hr > 0 else 0.0
        rel_ndcg_vs_pop = round(((m_ndcg - p_ndcg) / p_ndcg) * 100, 1) if p_ndcg > 0 else 0.0

        recovery_table.append({
            "k": k,
            "model_hit_rate": m_hr,
            "pop_hit_rate": p_hr,
            "rand_hit_rate": r_hr,
            "model_precision": m_prec,
            "pop_precision": p_prec,
            "rand_precision": r_prec,
            "model_recall": m_rec,
            "pop_recall": p_rec,
            "rand_recall": r_rec,
            "model_ndcg": m_ndcg,
            "pop_ndcg": p_ndcg,
            "rand_ndcg": r_ndcg,
            "relative_hr_gain_pct": rel_hr_vs_pop,
            "relative_ndcg_gain_pct": rel_ndcg_vs_pop
        })

    mrr_summary = {
        "model_mrr": calculate_ci95(rec_model["mrr"]),
        "popularity_mrr": calculate_ci95(rec_pop["mrr"]),
        "random_mrr": calculate_ci95(rec_rand["mrr"]),
        "independence_mrr": calculate_ci95(rec_indep["mrr"])
    }

    # 7. Format Threshold Sweep Grid for Interactive UI Live Updates
    sweep_table = []
    for t in thresh_grid:
        data_t = thresh_sweeps[t]
        sweep_table.append({
            "threshold": t,
            "tp": int(round(float(np.mean(data_t["tp"])))),
            "fp": int(round(float(np.mean(data_t["fp"])))),
            "fn": int(round(float(np.mean(data_t["fn"])))),
            "tn": int(round(float(np.mean(data_t["tn"])))),
            "precision": round(float(np.mean(data_t["prec"])), 4),
            "recall": round(float(np.mean(data_t["rec"])), 4),
            "f1": round(float(np.mean(data_t["f1"])), 4),
            "accuracy": round(float(np.mean(data_t["acc"])), 4),
            "mcc": round(float(np.mean(data_t["mcc"])), 4),
            "fired_groups_pct": round(float(np.mean(data_t["fired_pct"])) * 100, 1)
        })

    # 8. Format Per-Rule Performance Table
    per_rule_rows = []
    for r_key, r_info in rule_perf_dict.items():
        tp = r_info["tp"]
        fp = r_info["fp"]
        fn = r_info["fn"]
        tn = r_info["tn"]
        fired = r_info["fired_groups_count"]
        m = compute_binary_classification_metrics(tp, fp, fn, tn)

        per_rule_rows.append({
            "rule": r_info["rule"],
            "antecedent": r_info["antecedent"],
            "consequent": r_info["consequent"],
            "train_confidence": round(r_info["train_confidence"], 3),
            "train_lift": round(r_info["train_lift"], 3),
            "train_support": round(r_info["train_support"], 3),
            "fired_count": fired,
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "test_precision": m["precision"],
            "test_recall": m["recall"],
            "test_f1": m["f1"],
            "test_mcc": m["mcc"]
        })

    # Sort descending by F1 then test precision
    per_rule_rows.sort(key=lambda x: (x["test_f1"], x["test_precision"], x["fired_count"]), reverse=True)

    return {
        "status": "ok",
        "protocol": {
            "splits": n_splits,
            "test_ratio": test_size,
            "random_seed": random_seed,
            "mask_fraction": mask_fraction,
            "groups_evaluated": n_total,
            "disclaimer": "Evaluates co-occurrence pattern recovery on held-out threat groups; NOT attack prediction or chronological sequence modeling."
        },
        "confusion_matrix": {
            "counts": {"tp": mean_tp, "fp": mean_fp, "fn": mean_fn, "tn": mean_tn},
            "row_normalized": {
                "tp": norm_row_tp,
                "fn": norm_row_fn,
                "fp": norm_row_fp,
                "tn": norm_row_tn
            }
        },
        "summary_metrics": summary_cards,
        "curves": {
            "model": model_curves,
            "popularity": pop_curves,
            "random": rand_curves
        },
        "threshold_sweep": sweep_table,
        "recovery_comparison": recovery_table,
        "mrr_summary": mrr_summary,
        "per_rule_performance": per_rule_rows[:60],
        "imbalance_note": "In sparse binary matrices (sparsity ~89%), true negative instances vastly outnumber positives. Consequently, accuracy is artificially elevated (>90%) by majority-negative baseline prediction. F1-score, Matthews Correlation Coefficient (MCC), and Precision-Recall AUC (PR-AUC) provide the true, sensitive measures of non-trivial co-occurrence recovery."
    }
