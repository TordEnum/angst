from typing import Dict, Any, List, Tuple

class Checks:
    def __init__(self):
        self.check_confidence: Dict[str, float] = {}

    def assign_confidence(self, rule_pattern: str) -> float:
        # heuristic: longer patterns slightly less confident
        tokens = len((rule_pattern or "").split())
        conf = max(0.1, 1.0 - tokens * 0.05)
        self.check_confidence[rule_pattern] = conf
        return conf

    def is_redundant(self, a: str, b: str) -> bool:
        sa, sb = set(a.split()), set(b.split())
        return sa == sb or sa.issubset(sb) or sb.issubset(sa)

    def sanity_merge_allowed(self, a: str, b: str) -> bool:
        # prevent merging obvious conflicts: if they contain opposite intents
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
        # prioritize low-confidence for reinforcement
        out.sort(key=lambda x: x[1])
        return out
