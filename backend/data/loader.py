"""
Data loader and preprocessor for MITRE ATT&CK Enterprise XLSX dataset.
Parses enterprise-attack-v19.2.xlsx into binary transaction baskets.
Provides referential integrity validation, quality reports, dynamic filtering,
multi-lens support (Groups, Software, Campaigns), and abstraction level rollup
(Parent Techniques, Sub-Techniques, Tactics).
"""
import os
import json
from typing import Dict, List, Set, Tuple, Any, Optional
import pandas as pd


class AttackDataLoader:
    """Handles loading, cleaning, validating, and formatting MITRE ATT&CK transaction data."""

    def __init__(self, excel_path: str = "data/enterprise-attack-v19.2.xlsx"):
        self.excel_path = excel_path
        self._raw_cache: Optional[Dict[str, pd.DataFrame]] = None

    def _load_raw_sheets(self) -> Dict[str, pd.DataFrame]:
        """Loads and caches required Excel sheets."""
        if self._raw_cache is None:
            if not os.path.exists(self.excel_path):
                raise FileNotFoundError(f"MITRE ATT&CK dataset not found at {self.excel_path}")
            
            xl = pd.ExcelFile(self.excel_path)
            self._raw_cache = {
                "groups": xl.parse("groups"),
                "techniques": xl.parse("techniques"),
                "relationships": xl.parse("relationships"),
                "tactics": xl.parse("tactics"),
                "software": xl.parse("software"),
                "campaigns": xl.parse("campaigns")
            }
        return self._raw_cache

    def build_transactions(
        self,
        rollup_subtechniques: bool = True,
        min_techniques_per_group: int = 2,
        min_technique_frequency: int = 1,
        lens: str = "groups",
        abstraction: str = "parent"
    ) -> Dict[str, Any]:
        """
        Builds transaction matrix from verified ATT&CK relationships.
        
        Args:
            rollup_subtechniques: If True, sub-techniques (T1059.001) roll up to parent (T1059).
            min_techniques_per_group: Minimum items per entity to retain.
            min_technique_frequency: Minimum occurrence frequency for an item.
            lens: 'groups' | 'software' | 'campaigns'
            abstraction: 'parent' | 'subtechnique' | 'tactic'
            
        Returns:
            Dictionary with 'transactions', 'techniques', and 'metadata'.
        """
        sheets = self._load_raw_sheets()
        df_tech = sheets["techniques"].copy()
        df_rel = sheets["relationships"].copy()

        # Handle abstraction overrides
        if abstraction == "subtechnique":
            rollup_subtechniques = False
        elif abstraction == "parent":
            rollup_subtechniques = True

        # 1. Master Techniques Catalog
        techniques_catalog: Dict[str, Dict[str, Any]] = {}
        for _, row in df_tech.iterrows():
            tid = str(row["ID"]).strip() if pd.notnull(row["ID"]) else ""
            if not tid:
                continue
            
            raw_tactics = str(row.get("tactics", ""))
            tactics = [t.strip() for t in raw_tactics.split(",") if t.strip() and t.strip().lower() != "nan"]
            
            is_sub = bool(row.get("is sub-technique", False))
            sub_of = str(row.get("sub-technique of", "")) if pd.notnull(row.get("sub-technique of")) else None
            parent_id = sub_of if sub_of else tid.split(".")[0]

            techniques_catalog[tid] = {
                "id": tid,
                "name": str(row["name"]).strip() if pd.notnull(row["name"]) else tid,
                "tactics": tactics,
                "is_subtechnique": is_sub,
                "parent_id": parent_id
            }

        # 2. Master Entity Catalog for selected lens
        lens_clean = lens.lower()
        if lens_clean == "software":
            df_entity = sheets["software"].copy()
            source_type_filter = "software"
            entity_label = "software"
        elif lens_clean == "campaigns" or lens_clean == "campaign":
            df_entity = sheets["campaigns"].copy()
            source_type_filter = "campaign"
            entity_label = "campaign"
        else:
            df_entity = sheets["groups"].copy()
            source_type_filter = "group"
            entity_label = "group"

        entity_catalog: Dict[str, str] = {}
        for _, row in df_entity.iterrows():
            eid = str(row["ID"]).strip() if pd.notnull(row["ID"]) else ""
            ename = str(row["name"]).strip() if pd.notnull(row["name"]) else eid
            if eid:
                entity_catalog[eid] = ename

        # 3. Filter relationships for this lens
        total_rel_rows = len(df_rel)
        rel_uses = df_rel[
            (df_rel["mapping type"] == "uses") &
            (df_rel["source type"] == source_type_filter) &
            (df_rel["target type"] == "technique")
        ].copy()
        uses_count = len(rel_uses)

        dropped_orphans_entity = 0
        dropped_orphans_tech = 0
        raw_baskets: Dict[str, Set[str]] = {}

        for _, row in rel_uses.iterrows():
            source_id = str(row["source ID"]).strip() if pd.notnull(row["source ID"]) else ""
            target_id = str(row["target ID"]).strip() if pd.notnull(row["target ID"]) else ""

            if source_id not in entity_catalog:
                dropped_orphans_entity += 1
                continue
            if target_id not in techniques_catalog:
                dropped_orphans_tech += 1
                continue

            entity_name = entity_catalog[source_id]

            # Item determination based on abstraction
            if abstraction == "tactic":
                tactics = techniques_catalog[target_id].get("tactics", [])
                for tac in tactics:
                    raw_baskets.setdefault(entity_name, set()).add(tac)
            elif rollup_subtechniques:
                parent_id = target_id.split(".")[0]
                raw_baskets.setdefault(entity_name, set()).add(parent_id)
            else:
                raw_baskets.setdefault(entity_name, set()).add(target_id)

        # 4. Frequency & Minimum basket filtering
        item_freq_counter: Dict[str, int] = {}
        for items in raw_baskets.values():
            for itm in items:
                item_freq_counter[itm] = item_freq_counter.get(itm, 0) + 1

        rare_items = {itm for itm, freq in item_freq_counter.items() if freq < min_technique_frequency}
        filtered_transactions: Dict[str, List[str]] = {}
        dropped_small_entities = 0

        for entity, item_set in raw_baskets.items():
            valid_set = {itm for itm in item_set if itm not in rare_items}
            if len(valid_set) >= min_techniques_per_group:
                filtered_transactions[entity] = sorted(list(valid_set))
            else:
                dropped_small_entities += 1

        # 5. Build output metadata catalog for active items
        active_items: Set[str] = set()
        for itm_list in filtered_transactions.values():
            active_items.update(itm_list)

        output_catalog: Dict[str, Dict[str, Any]] = {}
        if abstraction == "tactic":
            for tac in active_items:
                output_catalog[tac] = {
                    "name": tac,
                    "tactics": [tac]
                }
        else:
            for itm in active_items:
                if itm in techniques_catalog:
                    output_catalog[itm] = {
                        "name": techniques_catalog[itm]["name"],
                        "tactics": techniques_catalog[itm]["tactics"]
                    }
                else:
                    parent_info = techniques_catalog.get(itm)
                    if parent_info:
                        output_catalog[itm] = {
                            "name": parent_info["name"],
                            "tactics": parent_info["tactics"]
                        }
                    else:
                        output_catalog[itm] = {
                            "name": itm,
                            "tactics": []
                        }

        # 6. Data quality report
        n_entities = len(filtered_transactions)
        n_items = len(output_catalog)
        basket_lengths = [len(ts) for ts in filtered_transactions.values()] if n_entities > 0 else [0]
        total_items = sum(basket_lengths)
        avg_basket = round(total_items / max(1, n_entities), 2)
        total_possible = n_entities * n_items
        density = round((total_items / max(1, total_possible)) * 100.0, 2)
        sparsity = round(100.0 - density, 2)

        metadata = {
            "source": self.excel_path,
            "version": "v19.2",
            "lens": lens_clean,
            "abstraction": abstraction,
            "rollup_subtechniques": rollup_subtechniques,
            "min_techniques_per_group": min_techniques_per_group,
            "min_technique_frequency": min_technique_frequency,
            "num_groups": n_entities,
            "num_techniques": n_items,
            "avg_basket_size": avg_basket,
            "min_basket_size": min(basket_lengths) if basket_lengths else 0,
            "max_basket_size": max(basket_lengths) if basket_lengths else 0,
            "sparsity_pct": sparsity,
            "density_pct": density,
            "total_technique_instances": total_items,
            "quality_report": {
                "total_relationships_in_dataset": total_rel_rows,
                "verified_uses_rows": uses_count,
                "dropped_orphaned_entities": dropped_orphans_entity,
                "dropped_orphaned_techniques": dropped_orphans_tech,
                "dropped_small_entities_count": dropped_small_entities,
                "dropped_rare_items_count": len(rare_items)
            }
        }

        return {
            "transactions": filtered_transactions,
            "techniques": output_catalog,
            "metadata": metadata
        }

    def cross_lens_validate(
        self,
        rules: List[Any],
        target_lens: str = "software"
    ) -> Dict[str, Any]:
        """
        Validates association rules mined on primary lens (Groups) against an independent secondary lens (Software/Campaigns).
        Tests whether the positive association (Lift > 1.0) holds in the target lens.
        """
        target_data = self.build_transactions(lens=target_lens, abstraction="parent")
        target_tx_sets = [set(ts) for ts in target_data["transactions"].values()]
        n_target = len(target_tx_sets)

        if n_target == 0 or not rules:
            return {
                "source_lens": "groups",
                "target_lens": target_lens,
                "target_transactions_count": n_target,
                "rules_tested": 0,
                "rules_holding": 0,
                "agreement_pct": 0.0,
                "rule_details": []
            }

        rule_details = []
        holds_count = 0
        tested_count = 0

        for r in rules:
            ante = r.antecedent if hasattr(r, "antecedent") else frozenset(r.get("raw_if", []))
            cons = r.consequent if hasattr(r, "consequent") else frozenset(r.get("raw_then", []))
            union_set = ante | cons

            c_ante = sum(1 for tx in target_tx_sets if ante.issubset(tx))
            c_cons = sum(1 for tx in target_tx_sets if cons.issubset(tx))
            c_both = sum(1 for tx in target_tx_sets if union_set.issubset(tx))

            if c_ante > 0 and c_cons > 0:
                tested_count += 1
                sup_both = c_both / float(n_target)
                sup_ante = c_ante / float(n_target)
                sup_cons = c_cons / float(n_target)
                target_lift = sup_both / (sup_ante * sup_cons)
                target_conf = float(c_both) / float(c_ante)
                holds = (target_lift > 1.0)
                if holds:
                    holds_count += 1

                rule_details.append({
                    "rule": f"{', '.join(sorted(ante))} -> {', '.join(sorted(cons))}",
                    "source_lift": getattr(r, "lift", 0.0),
                    "target_lift": round(target_lift, 3),
                    "target_confidence": round(target_conf, 3),
                    "target_support": round(sup_both, 4),
                    "holds_in_target": holds
                })

        agreement_pct = round((holds_count / max(1, tested_count)) * 100.0, 1)

        return {
            "source_lens": "groups",
            "target_lens": target_lens,
            "target_transactions_count": n_target,
            "rules_tested": tested_count,
            "rules_holding": holds_count,
            "agreement_pct": agreement_pct,
            "rule_details": rule_details[:30]
        }

    def to_dataframe(self, transactions: Dict[str, List[str]], techniques: Dict[str, Any]) -> pd.DataFrame:
        """Converts transactions dictionary to binary one-hot encoded DataFrame."""
        groups = list(transactions.keys())
        tech_cols = sorted(list(techniques.keys()))
        data = [[t in transactions[g] for t in tech_cols] for g in groups]
        return pd.DataFrame(data, index=groups, columns=tech_cols, dtype=bool)


# Global loader singleton
loader = AttackDataLoader()
