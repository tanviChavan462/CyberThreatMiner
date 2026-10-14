# CyberThreatMiner: Team Contributions & Evaluator Defense Guide
**Course:** 23PCIT503 - Machine Learning Mini Project  
**Project:** CyberThreatMiner: Adversarial Technique Association Mining Using Apriori & Modern Frequent Pattern Algorithms  
**Dataset:** MITRE ATT&CK Enterprise Matrix v19.2 (August 2026)  
**Academic Year:** 2026-2027  

---

## 1. Modular Division of Work (5 Team Members)

To ensure academic accountability, individual ownership, and deep viva defense preparedness, the system architecture is partitioned across 5 decoupled engineering modules:

```
+---------------------------------------------------------------------------------------------------+
|                                 CyberThreatMiner System Architecture                              |
+------------------------------------+--------------------------------------------------------------+
| Module 1: Data Engineering         | MITRE ATT&CK Ingestion, Multi-Lens, Hierarchies, Quality     |
| Module 2: Core Apriori & Mining    | Scratch Apriori, Downward Closure, Redundancy, Bias Filter   |
| Module 3: Advanced Algorithms      | FP-Growth, Eclat, Closed & Maximal Itemsets, Scalability     |
| Module 4: Statistics & Evaluation  | Fisher FDR, Vectorised Permutation, Train/Test 95% CI, Bases |
| Module 5: Visualization & UI       | Offline SPA (10 Tabs), Cytoscape Graph, Self-Check, Demo     |
+------------------------------------+--------------------------------------------------------------+
```

---

## 2. Member Profiles, Code Ownership, Demo Tasks & Viva Q&A

### Member 1: Data Engineering & Multi-Lens Architecture
- **Role:** Lead Data Engineer & Corpus Architect
- **Code Ownership:**
  - `backend/data/loader.py`: `AttackDataLoader` multi-lens and multi-abstraction pipeline
  - `backend/data/inspect_data.py`: Multi-sheet XLSX parsing & introspection
  - `prepare_data.py`: Preprocessing CLI, multi-lens JSON serialization (`transactions.json`, `transactions_software.json`, `transactions_campaigns.json`, `transactions_tactics.json`, `transactions_subtechniques.json`)
  - `docs/data_inspection.md`: Schema, entity relationships, and data quality audit
  - `tests/test_loader_quality.py`: Automated referential integrity and lens verification tests
- **Demo Responsibilities:**
  1. Demonstrate the live data ingestion statistics on the Overview tab (167 groups, 203 parent techniques, 89.02% sparsity, 0 orphaned rows).
  2. Toggle the **Analysis Lens** selector from *Threat Groups (167)* to *Software & Tools (785)* and *Campaigns (55)*, showing live KPI updates.
  3. Toggle the **Abstraction Level** selector between *Parent Techniques (203)*, *Sub-Techniques (350+)*, and *Tactics Rollup (14)*.
- **Individual Viva Defense Questions (5 Questions):**
  1. *Q: How does the data loader extract transactions from `enterprise-attack-v19.2.xlsx`?*  
     **Answer:** We parse the `relationships` worksheet where `source_type == 'intrusion-set'` (or `'malware'/'tool'`), map foreign keys to master `techniques` and `groups` sheets, deduplicate sub-techniques to parents, and filter actors with basket sizes $\ge 2$.
  2. *Q: Why is deduplication strictly required when rolling up sub-techniques?*  
     **Answer:** Threat actors frequently use multiple sub-techniques of a single parent (e.g. `T1059.001` PowerShell and `T1059.003` CMD). Without deduplication, the parent `T1059` would appear multiple times in the same transaction basket, violating the binary itemset set-membership assumption required by Apriori, FP-Growth, and Eclat.
  3. *Q: What does the 89.02% binary matrix sparsity signify for association mining?*  
     **Answer:** Out of 203 active techniques, each threat group exhibits an average of 22.28 techniques. High sparsity means that high-order candidate itemsets diminish rapidly, allowing downward closure to prune over 70% of candidate triplets before transaction scans.
  4. *Q: How is referential integrity validated across worksheets?*  
     **Answer:** Every technique ID in the relationship sheet must resolve to a non-revoked, non-deprecated technique object in the techniques catalog. Our automated test `test_loader_groups_quality_report` asserts zero orphaned relationship edges.
  5. *Q: What are the differences between the Threat Groups lens and the Software lens?*  
     **Answer:** The Threat Groups lens ($N=167$) captures human threat actor tradecraft across multi-year campaigns. The Software lens ($N=785$) captures individual malware family capabilities. Comparing both allows cross-lens generalizability testing.

---

### Member 2: Core Apriori Engine, Redundancy Pruning & Bias Control
- **Role:** Core Mining & Verification Specialist
- **Code Ownership:**
  - `backend/algorithms/apriori.py`: Scratch `AprioriMiner` class
  - `backend/algorithms/rules.py`: `AssociationRule` class, `generate_rules()`, popularity bias filter, and redundant rule pruning
  - `tests/test_apriori_math.py`: Hand-computed mathematical unit tests
  - `tests/test_algorithms_equivalence.py`: Mathematical cross-check against `mlxtend`
- **Demo Responsibilities:**
  1. Trigger mining on the Mine & Log tab with `min_support=0.25, min_confidence=0.70, min_lift=1.20`.
  2. Walk the evaluator through the **Apriori Level-wise Execution Log table**, highlighting Level 3 candidate generation (408 candidates generated, 286 pruned by downward closure, 50 frequent kept).
  3. Demonstrate the **Popularity Bias Filter** checkbox (capping ubiquitous items $> 70\%$ support, such as T1059) to show non-trivial tactical rules rising to the top.
- **Individual Viva Defense Questions (5 Questions):**
  1. *Q: Explain the Apriori property and how your code implements it.*  
     **Answer:** Anti-monotonicity of support dictates that every subset of a frequent itemset must also be frequent. Before checking database support for a candidate $k$-itemset, we verify that all $k$ of its $(k-1)$-subsets are present in $L_{k-1}$. If even one is missing, it is pruned immediately.
  2. *Q: How does your candidate generation $L_{k-1} \bowtie L_{k-1}$ avoid generating duplicate sets?*  
     **Answer:** We enforce a strict lexicographical ordering on items ($i_1 < i_2 < \dots$). Two itemsets $p$ and $q$ of size $k-1$ are joined only if they share their first $k-2$ items and $p[k-1] < q[k-1]$, ensuring each candidate is produced exactly once.
  3. *Q: How do you mathematically guarantee that your scratch implementation is correct?*  
     **Answer:** We verified correctness against a hand-calculated textbook 5-transaction matrix with fractional assertions, and via automated pytest comparison against `mlxtend.frequent_patterns.apriori`, achieving 100% itemset match with floating-point tolerance $< 10^{-6}$.
  4. *Q: What constitutes a redundant association rule, and how does your pruner work?*  
     **Answer:** A rule $A' \implies B$ is redundant with respect to a more general rule $A \implies B$ (where $A \subset A'$) if $\text{conf}(A' \implies B) \le \text{conf}(A \implies B)$. Adding extra prerequisite techniques to the antecedent without increasing confidence provides zero informational gain and is pruned.
  5. *Q: What is the Popularity Bias problem, and why does capping items at 70% support help?*  
     **Answer:** Techniques like `T1059 Command and Scripting Interpreter` occur in 74.3% of groups. Any rule predicting `T1059` achieves $>74\%$ confidence by random chance. Capping ubiquitous items forces the algorithm to discover specialized, actionable tradecraft.

---

### Member 3: Advanced Pattern Mining, Compression & Benchmarks
- **Role:** Pattern Mining & Algorithmic Performance Architect
- **Code Ownership:**
  - `backend/algorithms/fp_growth.py`: `FPGrowthMiner` & `FPNode` with prefix trees
  - `backend/algorithms/eclat.py`: `EclatMiner` with vertical tidset lattice traversal
  - `backend/algorithms/itemsets.py`: Closed and Maximal itemset extractors
  - `backend/algorithms/benchmarks.py`: Synthetic scaling benchmark harness with `tracemalloc` memory tracking
  - `tests/test_closed_maximal_hand.py`: Hand-built unit tests for closed/maximal sets
  - `tests/test_property_equivalence.py`: Property-based equivalence tests across random seeds
- **Demo Responsibilities:**
  1. Show that switching algorithms between Apriori, FP-Growth, and Eclat produces the exact same itemsets and support values in the Mine tab.
  2. Explain the **Closed Compression (0.7%, 142 closed)** and **Maximal Compression (46.9%, 76 maximal)** KPI cards.
  3. Walk through the **Algorithm Lab tab**, showing the synthetic scaling benchmark curves ($N \in \{500, 2000, 10000, 50000\}$) and explaining crossover points.
- **Individual Viva Defense Questions (5 Questions):**
  1. *Q: How does FP-Growth mine frequent patterns without candidate generation?*  
     **Answer:** It builds a compact prefix tree in 2 passes over the database. Mining proceeds recursively from the least frequent items upward by extracting conditional pattern bases (prefix paths), projecting conditional FP-trees, and avoiding candidate enumeration.
  2. *Q: How does Eclat work, and why is it fast on sparse binary matrices?*  
     **Answer:** Eclat uses a vertical layout where each item maps to a tidset of transaction IDs. Itemset support is computed via set intersection: $t(X \cup Y) = t(X) \cap t(Y)$. Set intersections run via native CPU bitwise operations without scanning the raw database.
  3. *Q: What is the mathematical distinction between Closed and Maximal itemsets?*  
     **Answer:** An itemset is closed if no proper superset has identical support ($\forall J \supset I, \text{supp}(J) < \text{supp}(I)$), preserving lossless support information. An itemset is maximal if no proper superset is frequent ($\forall J \supset I, \text{supp}(J) < \text{min\_sup}$), forming a lossy, compact boundary.
  4. *Q: Explain the asymptotic crossover points in your scaling benchmarks.*  
     **Answer:** At $N=500$, Apriori's lightweight setup is competitive. At $N=2,000$, Eclat and FP-Growth show an $8\times$ speedup. At $N=50,000$, Apriori experiences transaction scan bottlenecks ($2.56\text{ s}$), while Eclat completes in $244\text{ ms}$ ($10.5\times$ faster).
  5. *Q: What memory trade-offs exist between FP-Growth and Eclat?*  
     **Answer:** FP-Growth stores recursive conditional trees, requiring $11.16\text{ MB}$ at $N=50,000$. Eclat stores vertical tidsets requiring $6.57\text{ MB}$. Apriori uses the least memory ($270.8\text{ KB}$) but incurs massive time complexity.

---

### Member 4: Statistical Testing, ML Validation & Baselines
- **Role:** Statistical Rigor & Machine Learning Evaluation Engineer
- **Code Ownership:**
  - `backend/evaluation/statistical_tests.py`: Fisher's Exact Test, Benjamini-Hochberg FDR, and Vectorised Curveball Bipartite Permutation Null Model
  - `backend/evaluation/bootstrap.py`: Matrix-vectorised 100x Bootstrap resampling stability
  - `backend/evaluation/train_test.py`: 10-split repeated 80/20 train/test generalization validation with 95% CI
  - `backend/evaluation/classification_metrics.py`: Co-occurrence recovery on held-out threat groups, confusion matrix, threshold sweeps, ROC/PR curves, and 30% masked technique recovery
  - `backend/evaluation/baselines.py`: 5 benchmark comparison models (Lift-Ranked, Confidence-Only, Popularity Prior, Independence, Random)
  - `tests/test_statistical_math.py`: Unit tests for Fisher, FDR, permutation floor, and bootstrap determinism
  - `tests/test_train_test_gap.py`: Tests for train/test gap aggregation formulas
  - `tests/test_classification_metrics.py`: Comprehensive unit tests for confusion matrix, zero leakage, ROC/PR curves, and SLA budget
- **Demo Responsibilities:**
  1. Walk the evaluator through the **Evaluation tab**:
     - Point out the **Volcano Plot** ($x=\text{Lift}, y=-\log_{10}(q)$) with the $\alpha=0.05$ threshold line.
     - Show the **Bootstrap Stability Histogram** (100 iterations, most rules $\ge 90\%$ stable).
  2. Point out the **1,000 Permutations Runtime (~3.7s)** under the Curveball margin-preserving null model.
  3. Present the **Train/Test Generalization Card**: 10 splits, mean signed gap of $+2.68\% \pm 5.83\%$ (95% CI: $[-1.49\%, +6.84\%]$), test precision $79.55\%$.
  4. Demonstrate the **Co-occurrence Recovery Metrics Panel**:
     - Interactive Confusion Matrix (counts & row-normalized toggle: $75.5\%$ precision, $79.4\%$ specificity).
     - Live Confidence Threshold Slider ($\tau \in [0.50, 0.95]$) updating metrics dynamically from cached score vectors.
     - Grouped recovery bar chart comparing Model vs Popularity vs Random across $K \in \{1, 3, 5, 10\}$ (+$14.7\%$ gain at $K=1$, MRR $0.609$ vs $0.583$).
  5. Present the **5 Baselines Table**, explaining why Lift-Ranked ($1.70\times$ lift) outperforms Confidence-Only ($1.34\times$ lift).
- **Individual Viva Defense Questions (5 Questions):**
  1. *Q: Why is Benjamini-Hochberg FDR preferred over Bonferroni in association mining?*  
     **Answer:** Bonferroni controls FWER by dividing $\alpha$ by the number of tests ($0.05/174 = 0.00028$), which assumes independence and severely reduces statistical power. Benjamini-Hochberg controls the False Discovery Rate ($E[V/R] \le q$), sorting $p$-values and providing rigorous error control while preserving power for correlated techniques.
  2. *Q: Why is standard row/column shuffling invalid for bipartite threat actor data?*  
     **Answer:** Threat actors have highly variable basket sizes (2 to 78), and techniques follow power-law frequencies (1% to 74%). Uniform shuffling destroys these heavy-tailed marginals. The Curveball algorithm trades items exclusively between actors who do not share them, preserving every row degree and column degree exactly.
  3. *Q: Why is a permutation p-value floored at $1/(N+1)$ instead of displayed as 0?*  
     **Answer:** In Monte Carlo testing, the observed data itself counts as one permutation under the null hypothesis. With $N=1,000$ permutations, the minimum possible empirical p-value is $(1+0)/(1000+1) = 1/1001 \approx 0.000999$. Stating $p=0.0$ is mathematically erroneous; we display `"p < 0.001"`.
  4. *Q: How did you compute the 95% confidence interval for the generalization gap?*  
     **Answer:** We computed the gap across $K=10$ independent random 80/20 splits and used Student's $t$-distribution with $df=9$ degrees of freedom: $\bar{x} \pm t_{0.025, 9} \times \frac{s}{\sqrt{10}}$ where $t_{0.025, 9} = 2.262$. The resulting CI for signed gap $[-1.49\%, +6.84\%]$ spans zero, confirming no significant overfitting.
  5. *Q: Why does the Confidence-Only baseline have high precision but low net utility?*  
     **Answer:** Confidence-only greedily selects rules predicting `T1059` (base rate 74.3%). It achieves 93.7% precision simply by riding the high base rate, achieving only $1.34\times$ lift. Our Lift-ranked model achieves $1.70\times$ test lift and a $+0.255$ net advantage over independence.

---

### Member 5: Visualization, Offline Architecture & Cyber Defense Integration
- **Role:** Full-Stack & Systems Integration Engineer
- **Code Ownership:**
  - `static/index.html`: Responsive 10-tab dark-theme Single Page Application
  - `static/vendor/`: Offline local assets (`plotly.min.js`, `cytoscape.min.js`, `fonts.css`, local `.woff2` fonts)
  - `backend/algorithms/cooccur.py`: Threat actor fingerprinting and technique co-occurrence ranking
  - `backend/algorithms/clustering.py`: PCA 2D embedding, K-Means clustering, and multi-metric clustering quality (Silhouette, Davies-Bouldin, Calinski-Harabasz, Hierarchical Jaccard)
  - `backend/api/routes.py`: REST endpoints (`/api/summary`, `/api/mine`, `/api/statistical_eval`, `/api/train_test`, `/api/performance`, `/api/baselines`, `/api/multi_lens_eval`, `/api/self_check`, `/api/benchmarks`)
  - `app.py`: Flask application server with localhost-restricted CORS and debug flags
  - `tests/test_all_api_endpoints.py` & `tests/test_performance_budget.py`: API integration and response time SLA tests
- **Demo Responsibilities:**
  1. Trigger the **System Self-Check** card and click `🔄 Re-verify` to demonstrate live health verification.
  2. Navigate the **Cytoscape Network Graph**, demonstrate dragging nodes, filtering by Lift $> 1.5$, and switching layouts.
  3. Demonstrate **Threat Group Fingerprinting** on `APT28` and `Lazarus Group` in the Explorer tab.
  4. Trigger the **`▶ Live Demo`** automated guided tour and test the **`📄 Export`** report generation.
- **Individual Viva Defense Questions (5 Questions):**
  1. *Q: How does the application guarantee complete offline reliability?*  
     **Answer:** We eliminated all external CDN links. Plotly.js (4.5MB), Cytoscape.js (373KB), and 42 Google font binaries are vendored locally in `static/vendor/` with robust system font fallbacks, ensuring zero network requests outside localhost.
  2. *Q: How are server security and CORS configured in `app.py`?*  
     **Answer:** The server defaults to `debug=False` and binds strictly to `127.0.0.1`. CORS is restricted via regex to `http://127.0.0.1:*` and `http://localhost:*`, preventing unauthorized cross-origin requests.
  3. *Q: What does the System Self-Check endpoint `/api/self_check` verify?*  
     **Answer:** It verifies four core diagnostics in real time: (1) 167 groups and 203 techniques loaded with 0 orphaned rows, (2) Apriori, FP-Growth, and Eclat produce identical itemsets, (3) 100% agreement against `mlxtend` with support tolerance $<10^{-6}$, and (4) test suite status.
  4. *Q: Why is there an explicit ATT&CK Intelligence Notice banner on every page?*  
     **Answer:** MITRE ATT&CK associations are historical statistical co-occurrences, NOT chronological attack chains, NOT causal relationships, and subject to commercial reporting bias. Defensive analysts must know these are probabilistic correlation indicators, not deterministic predictions.
  5. *Q: How does threat group fingerprinting assist incident response teams?*  
     **Answer:** When responders observe an unknown adversary deploying techniques $T_1$ and $T_2$, the fingerprinting module calculates Jaccard similarity against all 167 documented threat groups and surfaces high-confidence companion techniques to prioritize log searches.

---

## 3. Comprehensive Deliverables & Ownership Matrix

| Project Deliverable | Primary Owner | Secondary Reviewer | Automated Test Verification |
|---|---|---|---|
| `data/enterprise-attack-v19.2.xlsx` Ingestion | Member 1 | Member 2 | `tests/test_loader_quality.py` |
| Multi-Lens & Hierarchies Serialization | Member 1 | Member 4 | `tests/test_loader_quality.py` |
| Scratch Apriori & Downward Closure | Member 2 | Member 3 | `tests/test_apriori_math.py` |
| 10 Rule Metrics & Redundancy Pruning | Member 2 | Member 4 | `tests/test_apriori_math.py` |
| `mlxtend` Golden Equivalence Verification | Member 2 | Member 3 | `tests/test_algorithms_equivalence.py` |
| Scratch FP-Growth & Eclat Engines | Member 3 | Member 2 | `tests/test_algorithms_equivalence.py` |
| Closed & Maximal Itemset Filters | Member 3 | Member 1 | `tests/test_closed_maximal_hand.py` |
| Synthetic Scalability Benchmark Engine | Member 3 | Member 5 | `tests/test_all_api_endpoints.py` |
| Fisher Exact & Benjamini-Hochberg FDR | Member 4 | Member 2 | `tests/test_statistical_math.py` |
| Curveball Margin-Preserving Permutation Model | Member 4 | Member 3 | `tests/test_statistical_math.py` |
| 10-Split Train/Test Generalization with 95% CI | Member 4 | Member 1 | `tests/test_train_test_gap.py` |
| Co-occurrence Recovery & Classification Metrics | Member 4 | Member 5 | `tests/test_classification_metrics.py` |
| 5 Baseline Models Benchmark Engine | Member 4 | Member 5 | `tests/test_all_api_endpoints.py` |
| 10-Tab SPA Dashboard & Dark Theme | Member 5 | Member 1 | Manual UI Verification |
| Offline Vendor Libraries & Font Packaging | Member 5 | All Members | Offline Network Audit |
| Cytoscape Network & Plotly Visualizations | Member 5 | Member 3 | `tests/test_all_api_endpoints.py` |
| Threat Actor Fingerprinting & Clustering Quality | Member 5 | Member 4 | `tests/test_all_api_endpoints.py` |
| One-Click Live Demo Mode & PDF Export | Member 5 | All Members | Live Demo Inspection |
