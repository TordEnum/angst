import hashlib, time
from dataclasses import dataclass
from typing import Dict, Any, List, Set, Tuple
from .config import DEFAULT_CONFIG, Config

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

    # ---- Rule management ----
    def _normalize_pattern(self, pattern: str) -> str:
        t = (pattern or "").strip().lower()
        parts = [p for p in t.split() if p]
        return " ".join(sorted(parts))

    def add_rule(self, pattern: str, weight: float = 1.0, seed: int | None = None) -> Rule:
        pat = self._normalize_pattern(pattern) if self.cfg.dedup_normalize else pattern
        rid = hashlib.sha1((pat + str(time.time()) + str(seed)).encode()).hexdigest()[:12]
        rule = Rule(id=rid, pattern=pat, weight=weight, provenance={"created": time.time(), "seed": seed})
        self.rules[rid] = rule
        return rule

    def all_rules(self) -> List[Rule]:
        return list(self.rules.values())

    # ---- Deduplication ----
    def deduplicate(self) -> Dict[str, Any]:
        by_pattern: Dict[str, List[Rule]] = {}
        for r in self.all_rules():
            by_pattern.setdefault(r.pattern, []).append(r)
        removed: List[str] = []
        for pat, group in by_pattern.items():
            if len(group) <= 1:
                continue
            # Keep the highest weight, merge provenance
            survivor = max(group, key=lambda r: r.weight)
            for r in group:
                if r.id == survivor.id:
                    continue
                survivor.provenance.setdefault("dedup_from", []).append(r.id)
                removed.append(r.id)
                self.rules.pop(r.id, None)
        return {"removed": removed, "kept": len(self.rules)}

    # ---- Hierarchical compression ----
    def _jaccard(self, a: Set[str], b: Set[str]) -> float:
        if not a or not b:
            return 0.0
        return len(a & b) / len(a | b)

    def _merge_patterns(self, a: str, b: str) -> str:
        sa, sb = set(a.split()), set(b.split())
        return " ".join(sorted(sa | sb))

    def compress(self, threshold: float | None = None, levels: int | None = None) -> Dict[str, Any]:
        thr = threshold if threshold is not None else self.cfg.compress_threshold
        max_levels = levels if levels is not None else self.cfg.hierarchical_levels
        # Pre-step: deduplicate
        dedup_info = self.deduplicate()
        initial_count = len(self.rules)
        total_removed: List[str] = list(dedup_info.get("removed", []))
        merges: List[Tuple[str, List[str]]] = []

        for level in range(max_levels):
            keys = list(self.rules.keys())
            changed = False
            # Prioritize merging lower-weight rules first into higher-weight ones
            keys.sort(key=lambda k: self.rules[k].weight)
            for i in range(len(keys)):
                a = self.rules.get(keys[i])
                if a is None:
                    continue
                sa = set(a.pattern.split())
                for j in range(i + 1, len(keys)):
                    b = self.rules.get(keys[j])
                    if b is None:
                        continue
                    sb = set(b.pattern.split())
                    jacc = self._jaccard(sa, sb)
                    if jacc >= thr:
                        # Merge lower-weight into higher-weight
                        dst, src = (b, a) if b.weight > a.weight else (a, b)
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
        efficiency = 0.0
        if initial_count > 0:
            efficiency = (initial_count - final_count) / initial_count
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
