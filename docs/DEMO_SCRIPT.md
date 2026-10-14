# CyberThreatMiner: 5-Minute Live Evaluator Demo Script
**Course:** 23PCIT503 - Machine Learning Mini Project  
**Target:** Final Academic Presentation, Project Defense & Evaluator Review  
**Presenter Roles:** Senior ML & Cybersecurity Engineering Pair  

---

## 1. Quick Reference & Setup

Before presenting to the evaluators, ensure the Flask development server is running and verified:
```bash
# Verify all 47 test suites are green (runs in ~23 seconds)
./run.sh test

# Launch the dashboard locally
./run.sh demo
# Dashboard opens automatically at: http://127.0.0.1:5001/
```

> **Pro-Tip for Presenters:** The dashboard includes an automated interactive tour! You can click the **`▶ Live Demo`** button in the header at any time, which automatically transitions through key tabs, highlights KPIs, and runs queries with a typing effect. Below is the full spoken presentation script.

---

## 2. Chronological 5-Minute Presentation Script

### Minute 0:00 &ndash; 1:00: Architecture, Data Ingestion & Live System Self-Check
**Tab:** `📊 Overview` (`http://127.0.0.1:5001/?tab=overview`)

* **What to Show:**
  1. Point to the **Green Diagnostic Card** at the top of the Overview tab:
     - `Data Ingestion: ✓ 167 Groups / 203 Techs (0 orphaned rows, 89.0% sparsity)`
     - `Equivalence: ✓ Apriori = FP-Growth = Eclat (100% itemset & support match)`
     - `mlxtend Standard: ✓ 100% Golden Agreement (Δ support < 10⁻⁶)`
     - `Test Suite: ✓ 47/47 PyTest Suites Passing`
  2. Point to the top metric cards (167 Threat Groups, 203 Parent Techniques, 22.28 Average Basket Density, 89.02% Matrix Sparsity).
  3. Show the **Prevalent Techniques Bar Chart** (T1059 Command and Scripting Interpreter at 74.3%, T1204 User Execution at 59.3%) and the **Kill-Chain Tactic Distribution**.

* **What to Say:**
  > *"Good afternoon, professors and evaluators. Today we present CyberThreatMiner, an adversarial tradecraft association mining and pattern analysis system built on the latest MITRE ATT&CK Enterprise Matrix v19.2.*
  >
  > *Before presenting any intelligence, we demonstrate computational reliability through our live System Self-Check banner. Our dataset consists of 167 documented threat actor intrusion-sets and 203 parent techniques, exhibiting an 89.02% binary matrix sparsity.*
  >
  > *Importantly, our three scratch algorithms—Apriori, FP-Growth, and Eclat—have been mathematically cross-verified against the industry-standard `mlxtend` golden reference, achieving 100% itemset agreement with numerical tolerance below $10^{-6}$. Our complete automated verification suite is currently 47 for 47 green."*

---

### Minute 1:00 &ndash; 2:00: Association Mining Engine & Downward Closure Logging
**Tab:** `⚙️ Mine & Log` (`http://127.0.0.1:5001/?tab=mine`)

* **What to Show:**
  1. On the left sidebar, show the threshold sliders:
     - Min Support: `0.25`
     - Min Confidence: `0.70`
     - Min Lift: `1.20`
     - Max Itemset Size: `3`
  2. Click **`⚡ Run Mining Query`**. Notice the execution time: **~35 ms**.
  3. Point out the **Apriori Level-wise Execution Log table**:
     - Level $k=1$: 203 candidates &rarr; 25 frequent itemsets kept.
     - Level $k=2$: 300 candidates generated ($25 \times 24 / 2$) &rarr; 68 frequent kept.
     - Level $k=3$: 408 candidates generated &rarr; **286 pruned immediately by downward closure** &rarr; 50 frequent kept.
  4. Highlight the **Closed (0.7% compression, 142 closed)** and **Maximal (46.9% compression, 76 maximal)** itemset metrics.
  5. Switch the dropdown from *Apriori* to *FP-Growth* and *Eclat*, showing identical itemset counts mined candidate-free.

* **What to Say:**
  > *"Now let's examine the core association mining engine. Here on the Mine & Log tab, we execute Apriori with a 25% minimum support and 70% confidence threshold.*
  >
  > *In Level 3, notice that out of 408 candidate triplets generated, exactly 286 were pruned prior to database scanning by invoking the downward closure property: if any subset of size 2 is infrequent, the superset cannot possibly be frequent. This reduces database scans by over 70%.*
  >
  > *We also extract closed and maximal itemsets. While all 143 frequent itemsets are represented, 76 maximal itemsets form the compact boundary, achieving a 46.9% lossy compression ratio, while 142 closed itemsets provide lossless support representation."*

---

### Minute 2:00 &ndash; 3:00: Mined Rules, Interactive Graph & Threat Actor Fingerprinting
**Tabs:** `📜 Rules`, `🕸️ Network Graph`, `🔍 Explorer & Fingerprint`

* **What to Show:**
  1. Switch to **`📜 Rules`** tab:
     - Show the rules sorted by Lift. Point out Rule #1: `T1105 Ingress Tool Transfer + T1566 Phishing ⇒ T1204 User Execution` (Confidence: 96.7%, Lift: 1.63x).
     - Point out the 10 mathematical metrics displayed per rule (Support, Confidence, Lift, Leverage, Conviction, Zhang, Cosine, Jaccard, Kulczynski, All-Confidence).
  2. Switch to **`🕸️ Network Graph`** tab:
     - Show the interactive Cytoscape network graph.
     - Nodes are color-coded by MITRE ATT&CK tactic; edge thickness corresponds to Lift.
     - Drag the **Min Lift filter slider** from 1.2x up to 1.6x to show dense clusters decoupling into high-confidence tactical cores.
  3. Switch to **`🔍 Explorer & Fingerprint`** tab:
     - Select **`APT28 (Fancy Bear)`** from the dropdown.
     - Show its documented profile: 31 techniques, 15.3% coverage.
     - Point out the **Signature Co-occurrences**: when APT28 deploys `T1566 Phishing`, the system identifies associated tradecraft with confidence ratings.

* **What to Say:**
  > *"Switching to the Rules tab, each discovered rule is evaluated across 10 distinct mathematical metrics. For example, the rule `Ingress Tool Transfer + Phishing implies User Execution` achieves 96.7% confidence and a Lift of 1.63, meaning user execution occurs 63% more frequently than baseline when this antecedent is observed.*
  >
  > *On the Network Graph tab, Cytoscape visualizes these inter-technique dependencies. Thick amber links indicate high-lift associations. When we filter for Lift > 1.5, we see distinct tactical hubs emerge around Execution, Persistence, and Defense Evasion.*
  >
  > *In the Explorer tab, defenders can enter an observed adversary like APT28 or Lazarus to compute their operational fingerprint and evaluate which associated techniques pose the highest probabilistic co-occurrence risk."*

---

### Minute 3:00 &ndash; 4:00: Statistical Rigor & Machine Learning Generalization
**Tab:** `📈 Evaluation` (`http://127.0.0.1:5001/?tab=evaluation`)

* **What to Show:**
  1. Point to the **Volcano Plot**:
     - X-axis: Rule Lift.
     - Y-axis: $-\log_{10}(q)$ Benjamini-Hochberg FDR.
     - Red dashed line: $\alpha = 0.05$ significance threshold ($-\log_{10}(0.05) \approx 1.301$).
     - Green points: Composite significant rules (Fisher $q < 0.05$ + Permutation $p < 0.05$ + Bootstrap stability $\ge 80\%$).
  2. Point to the **Bootstrap Stability Histogram**:
     - 100 resamples; most high-lift rules show 90% to 100% survival stability.
  3. Point to the **Permutation Test Status**:
     - Margin-preserving Curveball bipartite swap: 1,000 randomized trades executed in **~3.7 seconds**, strictly preserving actor basket size and technique degree.
  4. Point to the **Train/Test Generalization Card**:
     - Mean Train Confidence: **82.2%** (95% CI: [81.8%, 82.6%]).
     - Mean Test Confidence / Precision: **79.5%** (95% CI: [75.5%, 83.6%]).
     - Signed Generalization Gap: **$+2.68\% \pm 5.83\%$** (95% CI: [$-1.49\%$, $+6.84\%$]).
     - Absolute Gap: **$4.68\% \pm 4.19\%$**.

* **What to Say:**
  > *"This brings us to our primary scientific contribution: moving beyond raw frequency thresholds into empirical machine learning validation.*
  >
  > *First, we address multiple hypothesis testing. Mined rules undergo Fisher's exact test adjusted using Benjamini-Hochberg False Discovery Rate control. On our Volcano Plot, y-values reflect exact $-\log_{10}(q)$ scores exceeding 15, well above the $\alpha=0.05$ dashed threshold.*
  >
  > *Second, we implement a vectorised Curveball bipartite graph permutation model. By executing 1,000 margin-preserving Markov edge trades in 3.7 seconds, we preserve both actor basket sizes and technique degrees. This guarantees our p-values reflect true co-occurrence rather than technique popularity.*
  >
  > *Third, we evaluate generalization across 10 repeated 80/20 train/test splits. Our signed generalization gap is only +2.68%, with a 95% confidence interval spanning zero ($-1.49\%$ to $+6.84\%$). On unseen threat groups, our rules achieve 79.55% precision, demonstrating that our patterns do not overfit to historical noise."*

---

### Minute 4:00 &ndash; 5:00: Co-occurrence Recovery Metrics, Baselines & Caveats
**Tab:** `📈 Evaluation` (Scroll down to Co-occurrence Recovery & Baselines) and `ℹ️ About`

* **What to Show:**
  1. Point to the **Co-occurrence Recovery Metrics Panel**:
     - Show the **Interactive Confusion Matrix Heatmap** (Counts: TP 1619, FP 525, FN 1904, TN 2027; click **`Row-Normalized %`** to show 75.5% precision and 79.4% specificity).
     - Drag the **Confidence Threshold ($\tau$) Slider** live from 0.70 to 0.85: watch the metrics cards and confusion matrix recompute dynamically without re-mining!
     - Point out the **ROC Curve (AUC 0.640)** and **Precision-Recall Curve (AUC 0.702)** with Random and Popularity baselines overlaid.
     - Show the **Grouped Recovery Bar Chart**: at $K=1$, the model achieves **$52.1\%$ Hit-Rate vs $45.5\%$ Popularity** (+14.7% gain) and higher MRR ($0.609$ vs $0.583$).
  2. Point to the **5 Baseline Models Comparison Table**:
     - Show that **Lift-Ranked + Sig Filter** achieves **$1.70\times$ Test Lift** vs **$1.34\times$** for Confidence-Only, and $+0.255$ Net Advantage over Independence.
     - Explain why confidence-only ranking is biased toward ubiquitous techniques like `T1059`.
  3. Point to the **Multi-Lens Validation Card**:
     - External Agreement Rate: **94.0%** (156 out of 166 rules hold on 785 software dossiers with $\text{Lift} > 1.0$).
  4. Show the **Non-Causal Intelligence Disclaimer Badge** beside the panel:
     - Explicit caveat: Measures profile co-occurrence recovery on held-out threat groups, NOT chronological attack prediction.

* **What to Say:**
  > *"To answer the evaluator's fundamental question: 'Is this better than chance?', we evaluated co-occurrence recovery on held-out threat groups across 10 repeated splits with zero train/test leakage.*
  >
  > *Our interactive confusion matrix proves a 75.88% test precision with an MCC of +0.268, achieving a PR-AUC of 0.702. In our masked technique recovery test, where 30% of techniques are hidden per group, our model places the true missing technique at the top of the queue 52.1% of the time—a +14.7% relative advantage over global popularity priors.*
  >
  > *To test external validity, we projected rules mined from 167 Threat Groups onto an external corpus of 785 independent software dossiers. Exactly 94.0% of rules held with Lift > 1.0, proving that discovered tradecraft represents real technical synergies in software design.*
  >
  > *Finally, we conclude with an ethical and intelligence caveat: correlation is not causation. Discovered associations represent historical co-occurrences in vendor reporting, not chronological progression or deterministic future attacks.*
  >
  > *Thank you. We welcome your questions."*

---

## 3. Anticipated Live Demo Actions & Fallback Checklist

| Action During Demo | Expected Behavior | Verification Fallback |
| :--- | :--- | :--- |
| Click **`▶ Live Demo`** | Automatically opens tab walkthrough with animated modal | Press `Escape` or click `Exit Demo` to resume manual control |
| Click **`🔄 Re-verify`** in Self-Check | Button changes to `⏳ Checking...` then updates all 4 pills green | Run `./run.sh test` in terminal to display all 47 test results |
| Change **Lens** to `Software (785)` | Overview recalculates for 785 software profiles and re-renders charts | Select `Threat Groups (167)` to return to primary analysis |
| Click **`📄 Export`** in Header | Opens formatted, clean printable dossier suitable for PDF export | Uses native browser `window.print()` styles |
