from angst.rsl import RSL
from angst.config import DEFAULT_CONFIG

def test_rsl_parallel_eval():
    rsl = RSL(DEFAULT_CONFIG)
    variants = rsl.propose_variants(["declare intent", "act safe"], n=8)
    top = rsl.evaluate_variants(variants, steps=10, topk=3)
    assert len(top) == 3
    assert all("sim" in t and "score" in t["sim"] for t in top)
