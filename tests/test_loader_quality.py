"""
Data Loader Integrity & Multi-Lens Quality Tests:
Validates data ingestion, referential integrity, multi-lens loading, and abstraction levels.
"""
import pytest
import os
from backend.data.loader import AttackDataLoader


@pytest.fixture
def data_loader():
    excel_path = "data/enterprise-attack-v19.2.xlsx"
    if not os.path.exists(excel_path):
        pytest.skip(f"Dataset {excel_path} not available for testing")
    return AttackDataLoader(excel_path)


def test_loader_groups_quality_report(data_loader):
    """Asserts exact counts and zero referential integrity violations for threat group lens."""
    data = data_loader.build_transactions(lens="groups", abstraction="parent")
    meta = data["metadata"]
    q = meta["quality_report"]

    assert meta["num_groups"] == 167
    assert meta["num_techniques"] == 203
    assert meta["sparsity_pct"] > 85.0
    assert meta["density_pct"] < 15.0

    # Referential integrity checks: zero orphaned entities or techniques
    assert q["dropped_orphaned_entities"] == 0
    assert q["dropped_orphaned_techniques"] == 0


def test_loader_software_and_campaigns_lenses(data_loader):
    """Asserts successful extraction of Software and Campaign transaction matrices."""
    # Software lens
    soft_data = data_loader.build_transactions(lens="software", abstraction="parent")
    assert soft_data["metadata"]["num_groups"] >= 700  # 785 software dossiers
    assert len(soft_data["transactions"]) >= 700

    # Campaign lens
    camp_data = data_loader.build_transactions(lens="campaigns", abstraction="parent")
    assert camp_data["metadata"]["num_groups"] >= 40  # 55 campaigns
    assert len(camp_data["transactions"]) >= 40


def test_loader_tactics_and_subtechnique_abstractions(data_loader):
    """Asserts extraction of tactic-level and un-rolled sub-technique transaction matrices."""
    # Tactic level
    tac_data = data_loader.build_transactions(lens="groups", abstraction="tactic")
    assert tac_data["metadata"]["num_techniques"] <= 15  # ATT&CK enterprise tactics <= 15
    assert tac_data["metadata"]["density_pct"] > 50.0  # Tactics are dense

    # Sub-technique level
    sub_data = data_loader.build_transactions(lens="groups", abstraction="subtechnique")
    assert sub_data["metadata"]["num_techniques"] > 250  # More items than parent rollup
