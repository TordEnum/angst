import random
from typing import Dict, Any, List
from .config import DEFAULT_CONFIG, Config
from .kg import KnowledgeGraph
from .rsl import RSL
from .checks import Checks
from .logging_utils import Ledger

class Orchestrator:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.kg = KnowledgeGraph(cfg)
        self.rsl = RSL(cfg)
        self.checks = Checks()
        self.ledger = Ledger(cfg)
        self.history: List[Dict[str, Any]] = []

    def seed(self) -> None:
        random.seed(self.cfg.seed)
        self.kg.add_rule("declare_intent before external_call", weight=1.0, seed=42)
        self.kg.add_rule("verify_patch_proof before commit", weight=1.2, seed=43)
        self.kg.add_rule("compress_redundant_rules", weight=0.8, seed=44)

    def run(self) -> None:
        self.seed()
        stable_snapshot = self.kg.snapshot()
        last_best_score = 0.0
        for it in range(self.cfg.iterations):
            # Adaptive planning: if scores plateau, reduce iterations for self-improvement; else, explore more
            base_axioms = [r.pattern for r in self.kg.all_rules()]
            variants = self.rsl.propose_variants(base_axioms, n=self.cfg.variants_per_round)
            top = self.rsl.evaluate_variants(variants, steps=self.cfg.sim_steps, topk=self.cfg.topk_variants)

            materialized: List[str] = []
            for t in top:
                # materialize only a subset
                for ax in t["variant"]["axioms"][:2]:
                    r = self.kg.add_rule(ax, weight=1.0 + t["sim"]["score"] / 10.0, seed=t["variant"]["seed"])
                    materialized.append(r.id)

            # Targeted improvement: if compression has plateaued, emphasize checks
            comp = self.kg.compress(threshold=self.cfg.compress_threshold, levels=self.cfg.hierarchical_levels)
            checks_info = self.checks.strengthen_checks([r.pattern for r in self.kg.all_rules()])

            # Simple adaptive iteration logic based on score improvements
            best_score = max((t["sim"]["score"] for t in top), default=0.0)
            if best_score < last_best_score * 0.98:  # regression beyond noise
                if self.cfg.rollback_on_regression:
                    self.kg.restore(stable_snapshot)
            else:
                stable_snapshot = self.kg.snapshot()
                last_best_score = best_score

            entry = {
                "iteration": it,
                "top_variants": [{"seed": t["variant"]["seed"], "score": t["sim"]["score"]} for t in top],
                "materialized_rules": materialized,
                "compression": comp,
                "checks": checks_info[:5],  # preview
                "kg_size": len(self.kg.all_rules()),
            }
            self.ledger.append(entry)

        # Final summary entry
        agg = self.ledger.aggregate_metrics()
        anomalies = self.ledger.detect_anomalies()
        self.ledger.append({"summary": agg, "anomalies": anomalies})
