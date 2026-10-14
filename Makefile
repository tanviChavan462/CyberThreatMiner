.PHONY: test demo bench clean data

PYTHON ?= python3

test:
	$(PYTHON) -m pytest tests -v

demo:
	PORT=5001 $(PYTHON) app.py

bench:
	$(PYTHON) -c "from backend.algorithms.benchmarks import run_benchmark; import json; tx = [set(t) for t in json.load(open('data/transactions.json'))['transactions'].values()]; res = run_benchmark(tx, n_repeats=3); print(json.dumps(res, indent=2))"

data:
	$(PYTHON) prepare_data.py

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name ".DS_Store" -delete
	rm -rf .pytest_cache .coverage htmlcov

package: clean
	zip -r ../CyberThreatMiner_v3.zip . -x "*.git*" "*__pycache__*" "*.pytest_cache*" "*.DS_Store*" "*.zip"
	cp ../CyberThreatMiner_v3.zip ./CyberThreatMiner_v3.zip

