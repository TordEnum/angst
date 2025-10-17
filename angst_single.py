import os
import json
import time
import random
import hashlib
import statistics
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple, Set
from concurrent.futures import ThreadPoolExecutor


# =====================
# Config
# =====================
@dataclass
class Config:
    iterations: int = 8
    topk_variants: int = 4
    variants_per_round: int = 16
    sim_steps: int = 60
    compress_threshold: float = 0.6
    hierarchical_levels: int = 3
    dedup_normalize: bool = True
    exploration_epsilon: float = 0.2
    exploitation_weight: float = 0.7
    parallel_workers: int = 4
    rollback_on_regression: bool = True
    anomaly_z_threshold: float = 2.5
    out_dir: str = "out_angst_python"
    ledger_file: str = "ledger.jsonl"
    seed: int = 42


DEFAULT_CONFIG = Config()


# =====================
# Logging / Metrics
# =====================
class Ledger:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        os.makedirs(cfg.out_dir, exist_ok=True)
        self.path = os.path.join(cfg.out_dir, cfg.ledger_file)

    @staticmethod
    def now() -> float:
        return time.time()

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(entry)
        entry["ts"] = self.now()
        with open(self.path, "a", encoding="utf8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        return entry

    def aggregate_metrics(self) -> Dict[str, Any]:
        if not os.path.exists(self.path):
            return {}
        iterations, scores, effs = [], [], []
        with open(self.path, "r", encoding="utf8") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                it = obj.get("iteration")
                if it is None:
                    continue
                iterations.append(it)
                top = obj.get("top_variants", [])
                for t in top:
                    s = t.get("score")
                    if isinstance(s, (int, float)):
                        scores.append(float(s))
                comp = obj.get("compression", {})
                eff = comp.get("efficiency_score")
                if isinstance(eff, (int, float)):
                    effs.append(float(eff))
        out: Dict[str, Any] = {}
        if scores:
            out["avg_top_score"] = statistics.fmean(scores)
            out["var_top_score"] = statistics.pvariance(scores) if len(scores) > 1 else 0.0
        if effs:
            out["avg_compression_efficiency"] = statistics.fmean(effs)
        if iterations:
            out["iterations"] = max(iterations) + 1
        return out

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        scores: List[float] = []
        records: List[Dict[str, Any]] = []
        with open(self.path, "r", encoding="utf8") as f:
            for line in f:
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                top = obj.get("top_variants", [])
                it = obj.get("iteration")
                for t in top:
                    s = t.get("score")
                    if isinstance(s, (int, float)):
                        scores.append(float(s))
                        records.append({"iteration": it, "score": float(s)})
        if len(scores) < 6:
            return []
        mean = statistics.fmean(scores)
        stdev = statistics.pstdev(scores) or 1.0
        anomalies = []
        for r in records:
            z = (r["score"] - mean) / stdev
            if abs(z) >= DEFAULT_CONFIG.anomaly_z_threshold:
                anomalies.append({"iteration": r["iteration"], "score": r["score"], "z": z})
        return anomalies


# =====================
# Knowledge Graph / Rules
# =====================
@dataclass
class Rule:
    id: str
    pattern: str
    weight: float
    provenance: Dict[str, Any]


class KnowledgeGraph:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.rules: Dict[str, Rule] = {}
        self.snapshots: List[Dict[str, Any]] = []

    def _normalize_pattern(self, pattern: str) -> str:
        text = (pattern or "").strip().lower()
        parts = [p for p in text.split() if p]
        return " ".join(sorted(parts))

    def add_rule(self, pattern: str, weight: float = 1.0, seed: int | None = None) -> Rule:
        pat = self._normalize_pattern(pattern) if self.cfg.dedup_normalize else pattern
        rule_id = hashlib.sha1((pat + str(time.time()) + str(seed)).encode()).hexdigest()[:12]
        rule = Rule(id=rule_id, pattern=pat, weight=weight, provenance={"created": time.time(), "seed": seed})
        self.rules[rule_id] = rule
        return rule

    def all_rules(self) -> List[Rule]:
        return list(self.rules.values())

    def deduplicate(self) -> Dict[str, Any]:
        by_pattern: Dict[str, List[Rule]] = {}
        for r in self.all_rules():
            by_pattern.setdefault(r.pattern, []).append(r)
        removed: List[str] = []
        for pat, group in by_pattern.items():
            if len(group) <= 1:
                continue
            survivor = max(group, key=lambda r: r.weight)
            for r in group:
                if r.id == survivor.id:
                    continue
                survivor.provenance.setdefault("dedup_from", []).append(r.id)
                removed.append(r.id)
                self.rules.pop(r.id, None)
        return {"removed": removed, "kept": len(self.rules)}

    def _jaccard(self, a: Set[str], b: Set[str]) -> float:
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    def _merge_patterns(self, a: str, b: str) -> str:
        sa, sb = set(a.split()), set(b.split())
        return " ".join(sorted(sa | sb))

    def _sanity_merge_allowed(self, a: str, b: str) -> bool:
        forbidden_pairs = [("allow", "deny"), ("enable", "disable")]
        sa, sb = set(a.split()), set(b.split())
        for x, y in forbidden_pairs:
            if (x in sa and y in sb) or (y in sa and x in sb):
                return False
        return True

    def compress(self, threshold: float | None = None, levels: int | None = None) -> Dict[str, Any]:
        thr = threshold if threshold is not None else self.cfg.compress_threshold
        max_levels = levels if levels is not None else self.cfg.hierarchical_levels
        dedup_info = self.deduplicate()
        initial_count = len(self.rules)
        total_removed: List[str] = list(dedup_info.get("removed", []))
        merges: List[Tuple[str, List[str]]] = []

        for _level in range(max_levels):
            keys = list(self.rules.keys())
            changed = False
            # Prioritize merging lower-weight rules first into higher-weight ones
            keys.sort(key=lambda k: self.rules[k].weight)
            for i in range(len(keys)):
                rule_a = self.rules.get(keys[i])
                if rule_a is None:
                    continue
                set_a = set(rule_a.pattern.split())
                for j in range(i + 1, len(keys)):
                    rule_b = self.rules.get(keys[j])
                    if rule_b is None:
                        continue
                    set_b = set(rule_b.pattern.split())
                    jacc = self._jaccard(set_a, set_b)
                    if jacc >= thr and self._sanity_merge_allowed(rule_a.pattern, rule_b.pattern):
                        dst, src = (rule_b, rule_a) if rule_b.weight > rule_a.weight else (rule_a, rule_b)
                        dst.pattern = self._merge_patterns(dst.pattern, src.pattern)
                        dst.weight = max(dst.weight, src.weight) + 0.1
                        dst.provenance.setdefault("merged_from", []).append(src.id)
                        self.rules.pop(src.id, None)
                        total_removed.append(src.id)
                        merges.append((dst.id, [src.id]))
                        changed = True
            if not changed:
                break
        final_count = len(self.rules)
        efficiency = (initial_count - final_count) / initial_count if initial_count > 0 else 0.0
        return {
            "levels": max_levels,
            "removed": total_removed,
            "merged_into": {dst: srcs for dst, srcs in merges},
            "efficiency_score": efficiency,
            "final_count": final_count,
        }

    def snapshot(self) -> Dict[str, Any]:
        snap = {
            "ts": time.time(),
            "rules": {rid: {"pattern": r.pattern, "weight": r.weight, "prov": r.provenance} for rid, r in self.rules.items()},
        }
        self.snapshots.append(snap)
        return snap

    def restore(self, snapshot: Dict[str, Any]) -> None:
        self.rules = {}
        for rid, info in snapshot.get("rules", {}).items():
            self.rules[rid] = Rule(id=rid, pattern=info["pattern"], weight=info["weight"], provenance=info.get("prov", {}))


# =====================
# PHRE + RSL
# =====================
class PHRE:
    def simulate_seed(self, seed_id: int, axioms: List[str], steps: int = 50) -> Dict[str, Any]:
        rnd = random.Random(seed_id)
        trace, score = [], 0.0
        for s in range(steps):
            pick = axioms[s % len(axioms)]
            trace.append(f"step:{s} pick:{pick[:28]}")
            score += max(0.0, 1.0 / (1 + len(pick))) * (1 + 0.01 * s)
            if rnd.random() < 0.01:
                trace.append(f"attractor_jump:{s}")
                score *= 1.05
        return {"seed": seed_id, "trace": trace, "score": score}


class RSL:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.phre = PHRE()
        random.seed(cfg.seed)

    def propose_variants(self, base_axioms: List[str], n: int | None = None) -> List[Dict[str, Any]]:
        n = n or self.cfg.variants_per_round
        base = base_axioms or ["act safe", "declare intent"]
        variants: List[Dict[str, Any]] = []
        for _ in range(n):
            seed = random.randint(1, 1 << 30)
            mutated: List[str] = []
            for p in base:
                parts = p.split()
                if random.random() < 0.3:
                    parts.append(random.choice(["fast", "safe", "verify", "compress", "stronger"]))
                mutated.append(" ".join(parts))
            variants.append({"seed": seed, "axioms": mutated})
        return variants

    def evaluate_variants(self, variants: List[Dict[str, Any]], steps: int | None = None, topk: int | None = None) -> List[Dict[str, Any]]:
        steps = steps or self.cfg.sim_steps
        topk = topk or self.cfg.topk_variants
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=self.cfg.parallel_workers) as ex:
            futures = [ex.submit(self.phre.simulate_seed, v["seed"], v["axioms"], steps) for v in variants]
            for v, fut in zip(variants, futures):
                sim = fut.result()
                results.append({"variant": v, "sim": sim})
        for r in results:
            r["score_adj"] = r["sim"]["score"] * self.cfg.exploitation_weight + random.random() * self.cfg.exploration_epsilon
        results.sort(key=lambda x: x["score_adj"], reverse=True)
        return results[:topk]


# =====================
# Checks & Validation
# =====================
class Checks:
    def __init__(self):
        self.check_confidence: Dict[str, float] = {}

    def assign_confidence(self, rule_pattern: str) -> float:
        tokens = len((rule_pattern or "").split())
        conf = max(0.1, 1.0 - tokens * 0.05)
        self.check_confidence[rule_pattern] = conf
        return conf

    def is_redundant(self, a: str, b: str) -> bool:
        sa, sb = set(a.split()), set(b.split())
        return sa == sb or sa.issubset(sb) or sb.issubset(sa)

    def sanity_merge_allowed(self, a: str, b: str) -> bool:
        forbidden_pairs = [("allow", "deny"), ("enable", "disable")]
        for x, y in forbidden_pairs:
            if x in a.split() and y in b.split():
                return False
            if y in a.split() and x in b.split():
                return False
        return True

    def strengthen_checks(self, rules: List[str]) -> List[Tuple[str, float]]:
        out: List[Tuple[str, float]] = []
        seen: List[str] = []
        for r in rules:
            if any(self.is_redundant(r, s) for s in seen):
                continue
            seen.append(r)
            out.append((r, self.assign_confidence(r)))
        out.sort(key=lambda x: x[1])
        return out


# =====================
# Orchestrator
# =====================
class Orchestrator:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.kg = KnowledgeGraph(cfg)
        self.rsl = RSL(cfg)
        self.checks = Checks()
        self.ledger = Ledger(cfg)

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
            base_axioms = [r.pattern for r in self.kg.all_rules()]
            variants = self.rsl.propose_variants(base_axioms, n=self.cfg.variants_per_round)
            top = self.rsl.evaluate_variants(variants, steps=self.cfg.sim_steps, topk=self.cfg.topk_variants)

            materialized: List[str] = []
            for t in top:
                for ax in t["variant"]["axioms"][:2]:
                    r = self.kg.add_rule(ax, weight=1.0 + t["sim"]["score"] / 10.0, seed=t["variant"]["seed"])
                    materialized.append(r.id)

            comp = self.kg.compress(threshold=self.cfg.compress_threshold, levels=self.cfg.hierarchical_levels)
            checks_info = self.checks.strengthen_checks([r.pattern for r in self.kg.all_rules()])

            best_score = max((t["sim"]["score"] for t in top), default=0.0)
            if best_score < last_best_score * 0.98:
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
                "checks": checks_info[:5],
                "kg_size": len(self.kg.all_rules()),
            }
            self.ledger.append(entry)

        agg = self.ledger.aggregate_metrics()
        anomalies = self.ledger.detect_anomalies()
        self.ledger.append({"summary": agg, "anomalies": anomalies})


def main():
    print("Starting angst (python, single-file) ...")
    orch = Orchestrator(DEFAULT_CONFIG)
    orch.run()
    print("Done. Ledger at:", f"{DEFAULT_CONFIG.out_dir}/{DEFAULT_CONFIG.ledger_file}")


if __name__ == "__main__":
    main()
