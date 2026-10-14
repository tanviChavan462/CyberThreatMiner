"""
Builds data/transactions.json from official MITRE ATT&CK Enterprise Excel spreadsheet:
enterprise-attack-v19.2.xlsx.

Usage:
    python prepare_data.py [path/to/enterprise-attack-v19.2.xlsx] [--no-rollup] [--min-tech N] [--min-freq K]

Features:
- Validates 100% of referenced group IDs and technique IDs against master catalogs.
- Excludes revoked/deprecated objects.
- Deduplicates group-technique pairs resulting from sub-technique rollups.
- Preserves the standard output schema ({"transactions": {...}, "techniques": {...}}) with quality report metadata.
- Cross-checks statistics and logs data-quality report.
"""
import sys
import os
import json
import argparse
from backend.data.loader import AttackDataLoader


def main():
    parser = argparse.ArgumentParser(description="Preprocess MITRE ATT&CK Enterprise Excel dataset into transactions JSON.")
    parser.add_argument("excel_path", nargs="?", default="data/enterprise-attack-v19.2.xlsx",
                        help="Path to enterprise-attack-v19.2.xlsx")
    parser.add_argument("--no-rollup", action="store_true",
                        help="Keep sub-techniques separate instead of rolling up to parent techniques")
    parser.add_argument("--min-tech", type=int, default=2,
                        help="Minimum number of techniques per threat group (default: 2)")
    parser.add_argument("--min-freq", type=int, default=1,
                        help="Minimum frequency across groups for a technique to be retained (default: 1)")
    parser.add_argument("--output", default="data/transactions.json",
                        help="Target output path (default: data/transactions.json)")

    args = parser.parse_args()

    if not os.path.exists(args.excel_path):
        print(f"Error: Dataset file not found at {args.excel_path}")
        sys.exit(1)

    print(f"Loading and preprocessing from: {args.excel_path}")
    loader = AttackDataLoader(args.excel_path)
    dataset = loader.build_transactions(
        rollup_subtechniques=not args.no_rollup,
        min_techniques_per_group=args.min_tech,
        min_technique_frequency=args.min_freq
    )

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    # Also build multi-lens and abstraction datasets for instant offline loading
    data_dir = os.path.dirname(args.output)
    print("Building Software lens dataset...")
    ds_soft = loader.build_transactions(lens="software", abstraction="parent")
    with open(os.path.join(data_dir, "transactions_software.json"), "w", encoding="utf-8") as f:
        json.dump(ds_soft, f, indent=2)

    print("Building Campaign lens dataset...")
    ds_camp = loader.build_transactions(lens="campaigns", abstraction="parent")
    with open(os.path.join(data_dir, "transactions_campaigns.json"), "w", encoding="utf-8") as f:
        json.dump(ds_camp, f, indent=2)

    print("Building Tactics abstraction dataset...")
    ds_tac = loader.build_transactions(lens="groups", abstraction="tactic")
    with open(os.path.join(data_dir, "transactions_tactics.json"), "w", encoding="utf-8") as f:
        json.dump(ds_tac, f, indent=2)

    print("Building Sub-techniques abstraction dataset...")
    ds_sub = loader.build_transactions(lens="groups", abstraction="subtechnique")
    with open(os.path.join(data_dir, "transactions_subtechniques.json"), "w", encoding="utf-8") as f:
        json.dump(ds_sub, f, indent=2)

    meta = dataset["metadata"]
    q = meta["quality_report"]
    print("\n" + "="*60)
    print("DATA PREPARATION & QUALITY REPORT (Course 23PCIT503)")
    print("="*60)
    print(f"Source file:                   {meta['source']}")
    print(f"Rollup Sub-techniques:         {meta['rollup_subtechniques']}")
    print(f"Active Threat Groups:          {meta['num_groups']}")
    print(f"Active Techniques:             {meta['num_techniques']}")
    print(f"Average Basket Size:           {meta['avg_basket_size']} techniques/group")
    print(f"Min / Max Basket Size:         {meta['min_basket_size']} / {meta['max_basket_size']}")
    print(f"Matrix Sparsity:               {meta['sparsity_pct']}% (Density: {meta['density_pct']}%)")
    print(f"Total Group-Technique Links:   {meta['total_technique_instances']}")
    print("-" * 60)
    print("Referential Integrity & Cleaning Audit:")
    print(f"- Total Relationship Rows:     {q['total_relationships_in_dataset']:,}")
    print(f"- Group 'uses' Technique Rows: {q['verified_group_uses_technique_rows'] if 'verified_group_uses_technique_rows' in q else q.get('verified_uses_rows', 0):,}")
    print(f"- Orphaned Groups Dropped:     {q.get('dropped_orphaned_groups', q.get('dropped_orphaned_entities', 0))}")
    print(f"- Orphaned Techs Dropped:      {q['dropped_orphaned_techniques']}")
    print(f"- Groups < {args.min_tech} Techs Dropped:  {q.get('dropped_small_groups_count', q.get('dropped_small_entities_count', 0))}")
    print(f"- Rare Techs Dropped (< {args.min_freq}): {q.get('dropped_rare_techniques_count', q.get('dropped_rare_items_count', 0))}")
    print("="*60)
    print(f"Successfully generated -> {args.output}\n")


if __name__ == "__main__":
    main()
