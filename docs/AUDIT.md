# CyberThreatMiner: Architecture & Codebase Audit

**Course:** 23PCIT503 - Machine Learning Mini Project  
**Date:** October 2026  
**Auditor:** Antigravity Senior ML + Cybersecurity Engineering Pair  

---

## 1. Executive Summary

The initial `CyberThreatMiner` codebase implemented a prototype demonstration of association rule mining on MITRE ATT&CK data. While functional at a basic level, the codebase had significant structural, theoretical, and architectural gaps that prevent it from serving as a defensible, rigorous college mini-project.

This audit details the current state of each file, analyzes existing deficiencies against the official course requirements (Course 23PCIT503), documents what is retained, what is refactored, and defines our implementation plan.

---

## 2. File-by-File Audit

### 2.1 `prepare_data.py`
- **Current Role:** Loads MITRE ATT&CK STIX 2.1 JSON directly from a GitHub URL and extracts relationships into `data/transactions.json`.
- **Strengths:** 
  - Correctly identified intrusion-sets (`groups`) and attack-patterns (`techniques`).
  - Output format (`{"transactions": {...}, "techniques": {...}}`) is clean and intuitive.
- **Deficiencies:**
  - **Dataset Source:** Relies on STIX JSON rather than the officially mandated `enterprise-attack-v19.2.xlsx`.
  - **Data Validation & Cleaning:** Basic filter for `revoked` and `x_mitre_deprecated`, but no ID referential integrity verification against master entity lists, no tracking of dropped rows, and no data quality report.
  - **Granularity Flexibility:** Hardcoded roll-up of sub-techniques to parent techniques (`.split('.')[0]`), with no ability to toggle between parent and sub-technique granularity or filter groups by minimum transaction size.
- **Decision:** **REWRITE DATA PIPELINE**. Keep the clean JSON schema (`transactions`, `techniques`), but rewrite `prepare_data.py` to ingest the official `enterprise-attack-v19.2.xlsx` workbook (`relationships`, `groups`, `techniques`, `tactics`), validate every ID, produce a comprehensive data-quality report (`docs/data_inspection.md` and runtime metrics), and support dynamic roll-up options.

### 2.2 `app.py`
- **Current Role:** Flask backend exposing `/api/summary`, `/api/apriori`, `/api/clusters`, `/api/suggest`.
- **Strengths:** 
  - Lightweight single-file server, straightforward endpoints.
- **Deficiencies:**
  - **Algorithms:** Relies 100% on `mlxtend`'s blackbox `apriori()` and `association_rules()`. Does not implement Apriori from scratch. Does not implement FP-Growth or Eclat. Does not compute closed or maximal itemsets.
  - **Rule Metrics:** Only calculates `support`, `confidence`, and `lift`. Missing modern robust association measures (leverage, conviction, Zhang's metric, Jaccard, Kulczynski, cosine, all-confidence).
  - **Statistical Rigor:** Zero statistical validation. Rules are subject to spurious correlation from marginal technique popularity. Missing Fisher's exact test, Benjamini-Hochberg FDR correction, permutation null models, and bootstrap stability.
  - **Terminology & Cybersecurity Framing Flaw:** Endpoint `/api/suggest` and the UI tab "Next technique" imply chronological attack sequence prediction. In threat intelligence, group-technique associations represent observational co-occurrence across threat actor dossiers, **not** causal steps or chronological attack execution.
  - **Clustering:** Basic K-Means on Euclidean space with k=2..8 silhouette scores. Ignores Jaccard distance for high-dimensional sparse binary data, provides no hierarchical clustering option, no 2D dimensionality reduction (PCA/UMAP), and no cluster-level frequent itemsets.
  - **Evaluation:** No machine learning evaluation (no train/test split, no validation against mlxtend, no stability assessment).
- **Decision:** **MODULARIZE & REFACTOR BACKEND**.
  - Restructure into `backend/api/`, `backend/algorithms/`, `backend/evaluation/`, `backend/data/`.
  - Implement scratch versions of **Apriori** (with candidate generation and downward closure pruning logs), **FP-Growth**, and **Eclat**.
  - Keep `mlxtend` strictly as a golden reference for unit test cross-validation.
  - Replace `/api/suggest` with `/api/cooccur` ("Co-occurring techniques"), removing all predictive terminology and adding non-causal disclaimers.
  - Add comprehensive statistical validation and evaluation modules.

### 2.3 `static/index.html`
- **Current Role:** 3-tab frontend dashboard (Rules, Clusters, Next technique) styled with basic vanilla CSS.
- **Strengths:** Zero-build simplicity, fast loading, no complicated build pipelines.
- **Deficiencies:**
  - **Visualizations:** Lacks interactive charts, tactic distributions, and graph visualisations. No network graph connecting techniques and rules.
  - **Limited Exploration:** Tab structure does not support deep exploration of threat actor fingerprints, rule measures, algorithmic comparison, or statistical evaluation.
  - **Framing:** Tab labelled "Next technique" contradicts the project's strict non-predictive intelligence requirement.
  - **Aesthetics:** Functional but basic, lacking the visual polish, responsive dark-mode aesthetics, and interactive features expected of a top-tier project.
- **Decision:** **UPGRADE TO MULTI-TAB INTERACTIVE SPA**.
  - Implement a 10-tab dark-theme SPA using Vanilla JS + Plotly.js + Cytoscape.js.
  - Tabs: Overview, Mine, Itemsets, Rules, Network, Explorer, Algorithm Lab, Clusters, Evaluation, About/Limitations.
  - Include creative features: Threat Group Fingerprints, Plain-English Insight Cards, Tactic Co-occurrence Heatmap, One-Click Interactive Demo Mode, and Comprehensive Report Export.

### 2.4 `requirements.txt`
- **Current Role:** List of 4 dependencies (`flask`, `pandas`, `scikit-learn`, `mlxtend`).
- **Deficiencies:** Unpinned versions, missing `openpyxl` (mandatory for `.xlsx`), `scipy` (mandatory for Fisher exact test), `pytest` (for test suite), `plotly`, and reporting utilities.
- **Decision:** **UPDATE & PIN**. Provide a clean, pinned `requirements.txt`.

### 2.5 Tests and Documentation
- **Current State:** Completely absent. No test files, no audit documentation, no data inspection report, no contribution matrix.
- **Decision:** **BUILD EXTENSIVE TEST SUITE & DOCUMENTATION**.
  - `tests/`: Hand-computed unit test, algorithm equivalence test (Apriori == FP-Growth == Eclat == mlxtend), statistical validation tests, and Flask API integration tests.
  - `docs/`: `AUDIT.md`, `data_inspection.md`, `CONTRIBUTIONS.md`, architectural diagrams, and screenshots.

---

## 3. What We Keep vs What We Change

| Component | Status | Existing State | Refactored State | Rationale |
|---|---|---|---|---|
| **Data Format** | Kept & Enhanced | `{"transactions": {...}, "techniques": {...}}` | Same schema + data-quality metadata | Maintains clean contract while adding validation & rollup switches |
| **Data Source** | Changed | Online STIX JSON | Local MITRE `enterprise-attack-v19.2.xlsx` | Satisfies official requirement; reproducible offline |
| **Apriori Algorithm** | Replaced | Blackbox `mlxtend.apriori` | Pure Python scratch Apriori with level log | Course mini-project requirement; demonstrates algorithm mastery |
| **Alternative Mining** | Added | None | FP-Growth + Eclat from scratch | Algorithm comparison; benchmarks runtime & memory |
| **Itemsets** | Enhanced | Standard frequent sets | Frequent, Closed, and Maximal itemsets | Advanced association rule mining requirement |
| **Rule Metrics** | Expanded | Support, confidence, lift | 10 metrics: leverage, conviction, Zhang, Jaccard, Kulczynski, cosine, all-conf | Deep analytical evaluation |
| **Statistical Testing**| Added | None | Fisher exact test, Benjamini-Hochberg FDR, Permutation null test | Defensible, statistically valid rules |
| **Evaluation** | Added | None | 80/20 train-test splits, bootstrap stability (100x), mlxtend agreement | ML mini-project evaluation standard |
| **Clustering** | Enhanced | Basic KMeans | KMeans + Hierarchical (Jaccard & Euclidean), PCA 2D plot, cluster itemsets | Defensible grouping of threat actors |
| **Predictive Framing**| Fixed | "Next technique" / `/api/suggest` | "Co-occurring techniques" / `/api/cooccur` + disclaimer | Strict adherence to threat intel domain realities |
| **Frontend UI** | Upgraded | 3-tab minimal HTML | 10-tab Dark-mode SPA (Plotly, Cytoscape, Demo mode) | WOW factor, comprehensive interactive live demo |
| **Team Structure** | Added | Unspecified | 5-member modular roles & viva talking points (`CONTRIBUTIONS.md`) | Satisfies evaluation requirement |
| **Testing** | Added | 0 tests | 20+ automated tests in `pytest` | Engineering quality guarantee |

---

## 4. Implementation Plan

1. **Step 1: Data Pipeline (`prepare_data.py` & `docs/data_inspection.md`)**
   - Document all sheets, columns, and sample records of `enterprise-attack-v19.2.xlsx`.
   - Implement XLSX parsing with deduplication, revoked/deprecated filtering, parent/sub-technique options, and data quality metrics.
2. **Step 2: Core Mining Algorithms (`backend/algorithms/`)**
   - Implement Apriori from scratch with join-prune level logs.
   - Implement FP-Growth and Eclat from scratch.
   - Implement closed and maximal itemset filtering.
   - Implement 10 rule interest measures, redundant-rule filtering, and composite scoring.
3. **Step 3: Statistical Validation & Evaluation (`backend/evaluation/`)**
   - Implement Fisher's exact test and Benjamini-Hochberg FDR q-values.
   - Implement permutation matrix null model (bipartite degree-preserving swap).
   - Implement 100+ bootstrap resampling stability analysis.
   - Implement repeated 80/20 train/test evaluation and mlxtend equivalence benchmarks.
4. **Step 4: Clustering & Profiling (`backend/algorithms/clustering.py`)**
   - Implement Jaccard/Euclidean KMeans & Hierarchical Agglomerative clustering.
   - Compute PCA 2D coordinates for group visualization.
   - Mine per-cluster characteristic frequent itemsets.
5. **Step 5: API Layer (`backend/api/` & `app.py`)**
   - Modernize endpoints, integrate caching, and rename `/api/suggest` to `/api/cooccur`.
   - Expose endpoints for all algorithms, metrics, evaluation, fingerprints, and reports.
6. **Step 6: Unit & Integration Tests (`tests/`)**
   - Write tests for manual hand-calculation validation, algorithm equivalence, statistical tests, and API contracts.
7. **Step 7: Frontend Dashboard (`static/index.html`)**
   - Build 10-tab responsive dark-theme dashboard with Cytoscape network graph, Plotly charts, Algorithm Lab, Explorer, and Demo mode.
8. **Step 8: Verification, Documentation, & Packaging**
   - Run tests, start server, verify in browser, capture screenshots to `docs/screenshots/`.
   - Update `README.md` with architecture diagrams and viva questions.
   - Package `CyberThreatMiner_v2.zip`.
