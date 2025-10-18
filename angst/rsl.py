import random
from typing import List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from .config import DEFAULT_CONFIG, Config

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
        self.last_diversity: float = 0.0

    def _diversity(self, variants: List[Dict[str, Any]]) -> float:
        sets = [set(" ".join(v["axioms"]).split()) for v in variants]
        if len(sets) < 2:
            return 0.0
        dists = []
        for i in range(len(sets)):
            for j in range(i + 1, len(sets)):
                a, b = sets[i], sets[j]
                if not a and not b:
                    d = 0.0
                else:
                    d = 1.0 - (len(a & b) / len(a | b))
                dists.append(d)
        return sum(dists) / len(dists)

    def propose_variants(self, base_axioms: List[str], n: int | None = None) -> List[Dict[str, Any]]:
        n = n or self.cfg.variants_per_round
        base = base_axioms or ["act safe", "declare intent"]
        variants: List[Dict[str, Any]] = []
        for _ in range(n):
            seed = random.randint(1, 1 << 30)
            mutated: List[str] = []
            for p in base:
                parts = p.split()
                # exploration: occasionally add modifiers
                if random.random() < 0.3:
                    parts.append(random.choice(["fast", "safe", "verify", "compress", "stronger"]))
                mutated.append(" ".join(parts))
            variants.append({"seed": seed, "axioms": mutated})
        self.last_diversity = self._diversity(variants)
        return variants

    def evaluate_variants(self, variants: List[Dict[str, Any]], steps: int | None = None, topk: int | None = None) -> List[Dict[str, Any]]:
        steps = steps or self.cfg.sim_steps
        topk = topk or self.cfg.topk_variants
        # parallel evaluation
        results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=self.cfg.parallel_workers) as ex:
            futures = [ex.submit(self.phre.simulate_seed, v["seed"], v["axioms"], steps) for v in variants]
            for v, fut in zip(variants, futures):
                sim = fut.result()
                results.append({"variant": v, "sim": sim})
        # weighted exploitation-exploration sorting
        # add small noise to encourage exploration
        for r in results:
            r["score_adj"] = (
                r["sim"]["score"] * self.cfg.exploitation_weight
                + random.random() * self.cfg.exploration_epsilon
                + 0.1 * self.last_diversity
            )
        results.sort(key=lambda x: x["score_adj"], reverse=True)
        return results[:topk]
