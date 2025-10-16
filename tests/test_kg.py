from angst.kg import KnowledgeGraph
from angst.config import DEFAULT_CONFIG

def test_dedup_and_compress_runs():
    kg = KnowledgeGraph(DEFAULT_CONFIG)
    kg.add_rule("a b c")
    kg.add_rule("a b c")
    kg.add_rule("a b d")
    info = kg.compress()
    assert "efficiency_score" in info
    assert info["final_count"] >= 1
