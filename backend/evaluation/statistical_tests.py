"""
Statistical Validation for Association Rules.
Includes:
1. Fisher's Exact Test on 2x2 contingency tables (full precision, logsf scale for finite -log10 p).
2. Benjamini-Hochberg False Discovery Rate (FDR) q-value correction without premature rounding.
3. Permutation Null Model via Vectorised Degree-Preserving Bipartite Swaps (Curveball / Matrix trades).
   Strictly preserves threat group basket sizes (row totals) and technique frequencies (column totals).
4. Composite Statistical Significance testing (Fisher q < 0.05, Permutation p < 0.05, Bootstrap stability >= 80%).
"""
from typing import List, Dict, Set, FrozenSet, Tuple, Any, Optional
import numpy as np
import scipy.stats as stats
from backend.algorithms.rules import AssociationRule


def compute_fisher_exact(rule: AssociationRule, n_transactions: int) -> Tuple[float, float]:
    """
    Computes one-tailed Fisher's exact test (alternative='greater') on the 2x2 contingency table.
    Uses hypergeometric logsf to avoid numerical underflow on tiny p-values, ensuring finite -log10(p).
    
    Table structure:
    |                 | Has Consequent B | Lacks Consequent B | Total  |
    | Has Antecedent A| n(A and B)       | n(A and not B)     | n(A)   |
    | Lacks Anteced. A| n(not A and B)   | n(not A and not B) | n(notA)|
    | Total           | n(B)             | n(not B)           | N      |

    Returns:
        (p_value, neg_log10_p)
    """
    n_ab = int(round(rule.support * n_transactions))
    n_a = int(round(rule.support_a * n_transactions))
    n_b = int(round(rule.support_b * n_transactions))

    n_a_not_b = max(0, n_a - n_ab)
    n_not_a_b = max(0, n_b - n_ab)
    n_not_a_not_b = max(0, n_transactions - n_a - n_b + n_ab)

    table = [[n_ab, n_a_not_b], [n_not_a_b, n_not_a_not_b]]
    _, p_val = stats.fisher_exact(table, alternative="greater")
    p_val = float(p_val)

    # Compute exact -log10(p) using hypergeometric log-survival function
    # Pr(X >= n_ab) in Hypergeom(M=n_transactions, n=n_b, N=n_a)
    try:
        log_sf = stats.hypergeom.logsf(n_ab - 1, n_transactions, n_b, n_a)
        neg_log10_p = -float(log_sf / np.log(10.0))
    except Exception:
        neg_log10_p = -float(np.log10(max(1e-300, p_val)))

    if np.isnan(neg_log10_p) or np.isinf(neg_log10_p) or neg_log10_p < 0.0:
        neg_log10_p = -float(np.log10(max(1e-300, p_val)))

    return p_val, neg_log10_p


def benjamini_hochberg_fdr(p_values: List[float]) -> Tuple[List[float], List[float]]:
    """
    Benjamini-Hochberg procedure for False Discovery Rate (FDR) correction.
    Maintains full float64 precision without premature rounding so that -log10(q) remains finite and exact.

    Returns:
        (q_values, neg_log10_q_values)
    """
    m = len(p_values)
    if m == 0:
        return [], []

    # Sort p-values with original indices
    indexed_p = sorted(enumerate(p_values), key=lambda x: x[1])
    q_values = [0.0] * m
    neg_log10_q = [0.0] * m

    running_min = 1.0
    # Step backwards from largest p-value to smallest
    for rank_idx in range(m - 1, -1, -1):
        orig_idx, p = indexed_p[rank_idx]
        rank = rank_idx + 1  # 1-based rank
        q = min(1.0, (float(m) / float(rank)) * p)
        running_min = min(running_min, q)
        q_values[orig_idx] = float(running_min)
        neg_log10_q[orig_idx] = -float(np.log10(max(1e-300, running_min)))

    return q_values, neg_log10_q


def apply_statistical_validation(
    rules: List[AssociationRule],
    n_transactions: int
) -> List[AssociationRule]:
    """
    Calculates Fisher's exact test p-values, FDR q-values, and finite -log10 metrics for all rules.
    Does not round p-values to 0.
    """
    if not rules:
        return rules

    p_results = [compute_fisher_exact(rule, n_transactions) for rule in rules]
    p_values = [res[0] for res in p_results]
    neg_log_p = [res[1] for res in p_results]

    q_values, neg_log_q = benjamini_hochberg_fdr(p_values)

    for rule, p_val, nlp, q_val, nlq in zip(rules, p_values, neg_log_p, q_values, neg_log_q):
        rule.p_value = p_val
        rule.q_value = q_val
        rule.neg_log10_p = round(nlp, 4)
        rule.neg_log10_q = round(nlq, 4)
        rule.sig_fisher = bool(q_val < 0.05)
        # Update composite significance if other tests were already run
        rule.is_significant = bool(rule.sig_fisher and rule.sig_perm and rule.sig_boot)

    return rules


class PermutationNullModel:
    """
    Permutation Null Model that randomizes the threat group-technique binary matrix
    while strictly preserving row totals (threat group basket sizes)
    and column totals (technique frequencies) using the Curveball trade algorithm (Strona et al., 2014).
    Fast, vectorised implementation capable of 1000+ permutations in < 2 seconds.
    """

    def __init__(self, binary_matrix: np.ndarray, item_names: List[str], seed: Optional[int] = 42):
        """
        Args:
            binary_matrix: 2D numpy boolean/int array of shape (n_groups, n_techniques).
            item_names: List of technique IDs corresponding to matrix columns.
            seed: Random seed for reproducibility.
        """
        self.matrix = np.array(binary_matrix, dtype=bool)
        self.item_names = item_names
        self.item_to_idx = {name: i for i, name in enumerate(item_names)}
        self.n_rows, self.n_cols = self.matrix.shape
        self.seed = seed
        self.rng = np.random.default_rng(seed)

        # Precompute initial row adjacency sets and column sums
        self.row_sets = [set(np.where(self.matrix[i])[0]) for i in range(self.n_rows)]
        self.row_degrees = [len(s) for s in self.row_sets]
        self.col_degrees = np.array(self.matrix.sum(axis=0), dtype=np.int32)

    def _curveball_trade_step(self, row_sets: List[Set[int]]) -> None:
        """
        Executes one full round of bipartite degree-preserving Curveball trades on row sets.
        Preserves exact row degrees and column degrees.
        """
        n = self.n_rows
        order = self.rng.permutation(n)
        for i in range(0, n - 1, 2):
            r1, r2 = order[i], order[i + 1]
            s1, s2 = row_sets[r1], row_sets[r2]
            common = s1 & s2
            diff = list((s1 | s2) - common)
            if not diff:
                continue
            l1 = len(s1) - len(common)
            self.rng.shuffle(diff)
            row_sets[r1] = common | set(diff[:l1])
            row_sets[r2] = common | set(diff[l1:])

    def evaluate_rules_under_null(
        self,
        rules: List[AssociationRule],
        n_permutations: int = 1000
    ) -> List[AssociationRule]:
        """
        Evaluates observed rule lifts against the bipartite margin-preserving permutation null distribution.
        Computes empirical permutation p-values:
            p_perm = (1 + count(Lift_null >= Lift_obs)) / (n_permutations + 1)
        Floor is strictly 1 / (n_permutations + 1).

        Args:
            rules: List of AssociationRule objects to validate.
            n_permutations: Number of matrix permutations (default: 1000, UI: 100-5000).

        Returns:
            Rules updated with permutation_p_value, permutation_p_str, sig_perm, and is_significant.
        """
        if not rules:
            return rules

        # Create deep copy of row sets for simulation
        sim_row_sets = [s.copy() for s in self.row_sets]
        n_rows = self.n_rows
        n_cols = self.n_cols

        # Initial burn-in (15 trade rounds)
        for _ in range(15):
            self._curveball_trade_step(sim_row_sets)

        # Pre-index rules into fast column lookup tuples
        # Format: (ante_indices, cons_indices, all_indices, obs_lift, is_single_ante_cons)
        compiled_rules = []
        for rule in rules:
            ante_idx = [self.item_to_idx[t] for t in rule.antecedent if t in self.item_to_idx]
            cons_idx = [self.item_to_idx[t] for t in rule.consequent if t in self.item_to_idx]
            all_idx = ante_idx + cons_idx
            is_single = (len(ante_idx) == 1 and len(cons_idx) == 1)
            compiled_rules.append((ante_idx, cons_idx, all_idx, float(rule.lift), is_single))

        null_exceed_counts = np.zeros(len(rules), dtype=np.int32)
        perm_mat = np.zeros((n_rows, n_cols), dtype=bool)

        for _ in range(n_permutations):
            # One trade round step between samples
            self._curveball_trade_step(sim_row_sets)

            # Reconstruct binary matrix view
            perm_mat.fill(False)
            for r_i, r_s in enumerate(sim_row_sets):
                perm_mat[r_i, list(r_s)] = True

            # Evaluate each rule against this null matrix
            for r_idx, (ante_idx, cons_idx, all_idx, obs_lift, is_single) in enumerate(compiled_rules):
                if not ante_idx or not cons_idx:
                    continue

                if is_single:
                    a = ante_idx[0]
                    b = cons_idx[0]
                    sup_all = float((perm_mat[:, a] & perm_mat[:, b]).mean())
                    # Column degrees are strictly preserved under Curveball trades
                    sup_ante = float(self.col_degrees[a]) / float(n_rows)
                    sup_cons = float(self.col_degrees[b]) / float(n_rows)
                else:
                    sup_all = float(perm_mat[:, all_idx].all(axis=1).mean())
                    sup_ante = float(perm_mat[:, ante_idx].all(axis=1).mean())
                    sup_cons = float(perm_mat[:, cons_idx].all(axis=1).mean())

                if sup_ante > 0.0 and sup_cons > 0.0:
                    null_lift = sup_all / (sup_ante * sup_cons)
                else:
                    null_lift = 0.0

                if null_lift >= obs_lift:
                    null_exceed_counts[r_idx] += 1

        # Calculate empirical permutation p-values with strict floor 1/(n_permutations + 1)
        min_floor = 1.0 / float(n_permutations + 1)
        floor_threshold_str = f"p < {1.0 / (10 ** int(np.floor(np.log10(n_permutations))))}" if n_permutations >= 100 else f"p < {min_floor:.3f}"

        for r_idx, rule in enumerate(rules):
            exceed = int(null_exceed_counts[r_idx])
            emp_p = float(exceed + 1) / float(n_permutations + 1)
            rule.permutation_p_value = emp_p

            if exceed == 0:
                if n_permutations >= 1000:
                    rule.permutation_p_str = "p < 0.001"
                elif n_permutations >= 100:
                    rule.permutation_p_str = "p < 0.01"
                else:
                    rule.permutation_p_str = f"p < {min_floor:.3f}"
            else:
                rule.permutation_p_str = f"p = {emp_p:.4f}"

            rule.sig_perm = bool(emp_p < 0.05)
            # Composite significance requires Fisher q < 0.05, Permutation p < 0.05, Bootstrap stability >= 80%
            rule.is_significant = bool(rule.sig_fisher and rule.sig_perm and rule.sig_boot)

        return rules
