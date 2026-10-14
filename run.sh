#!/usr/bin/env bash
# ==============================================================================
# CyberThreatMiner: Universal Execution Script
# Course: 23PCIT503 - Machine Learning Mini Project
# Usage:
#   ./run.sh          -> Launch live interactive application dashboard
#   ./run.sh demo     -> Launch live interactive application dashboard
#   ./run.sh test     -> Run full 41+ PyTest verification test suite
#   ./run.sh bench    -> Run algorithm benchmarks (Apriori vs FP-Growth vs Eclat)
#   ./run.sh data     -> Rebuild all transactions from enterprise-attack-v19.2.xlsx
# ==============================================================================

set -e

CMD=${1:-demo}

echo "=============================================================="
echo "⚡ CyberThreatMiner (MITRE ATT&CK Association Mining) [23PCIT503]"
echo "=============================================================="

case "$CMD" in
    test)
        echo "🧪 Running full PyTest verification suite..."
        python3 -m pytest tests -v
        ;;

    bench)
        echo "⚡ Executing algorithmic runtime & scalability benchmarks..."
        python3 -c "
from backend.algorithms.benchmarks import run_benchmark
import json
with open('data/transactions.json') as f:
    tx = [set(t) for t in json.load(f)['transactions'].values()]
res = run_benchmark(tx, n_repeats=3)
print('\n--- REAL MITRE ATT&CK DATASET BENCHMARK (167 Groups) ---')
for i, sup in enumerate(res['supports']):
    print(f'min_support={sup:.2f} | Items={res[\"itemset_counts\"][i]:3d} | Apriori: {res[\"apriori_time_ms\"][i]:5.2f} ms | FP-Growth: {res[\"fp_growth_time_ms\"][i]:5.2f} ms | Eclat: {res[\"eclat_time_ms\"][i]:5.2f} ms')

print('\n--- SYNTHETIC SCALING BENCHMARK (500 to 50,000 Transactions) ---')
scale = res['scaling_benchmark']
for i, n in enumerate(scale['transaction_sizes']):
    print(f'N={n:5d} txs | Apriori: {scale[\"apriori_ms\"][i]:7.2f} ms | FP-Growth: {scale[\"fp_growth_ms\"][i]:6.2f} ms | Eclat: {scale[\"eclat_ms\"][i]:6.2f} ms')
print('\nEquivalence Verified:', res['equivalence_verified'])
print('Assessment:', res['honest_assessment'])
"
        ;;

    data)
        echo "⚙️ Preparing datasets from data/enterprise-attack-v19.2.xlsx..."
        python3 prepare_data.py
        ;;

    demo|start|"")
        # Ensure data is present
        if [ ! -f "data/transactions.json" ]; then
            echo "⚙️ Preparing dataset from data/enterprise-attack-v19.2.xlsx..."
            python3 prepare_data.py
        fi

        PORT=${PORT:-5001}
        echo "🚀 Launching application dashboard on http://127.0.0.1:$PORT"
        echo "Press Ctrl+C to terminate."
        python3 app.py
        ;;

    *)
        echo "Unknown option: $CMD"
        echo "Usage: ./run.sh [demo|test|bench|data]"
        exit 1
        ;;
esac
