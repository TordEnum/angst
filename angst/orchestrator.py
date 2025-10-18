import random
from typing import Dict, Any, List
from .config import DEFAULT_CONFIG, Config
from .kg import KnowledgeGraph
from .rsl import RSL
from .checks import Checks
from .logging_utils import Ledger
from dataclasses import dataclass
from typing import Tuple


# ---- Causal Modeler (symbolic regression via simple basis expansion + SGD) ----
@dataclass
class CausalModel:
    coefficients: Dict[str, float]
    intercept: float


class CausalModeler:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg

    def _features(self, x: float) -> Dict[str, float]:
        # Polynomial basis up to cfg.causal_max_degree
        feats: Dict[str, float] = {"x": x}
        for d in range(2, self.cfg.causal_max_degree + 1):
            feats[f"x^{d}"] = x ** d
        return feats

    def fit(self, xs: List[float], ys: List[float]) -> CausalModel:
        # Simple online SGD on linearized basis
        coef: Dict[str, float] = {}
        intercept = 0.0
        keys = list(self._features(0.0).keys())
        for k in keys:
            coef[k] = 0.0
        lr = self.cfg.causal_learning_rate
        for _ in range(self.cfg.causal_steps):
            for x, y in zip(xs, ys):
                feats = self._features(x)
                y_hat = intercept + sum(coef[k] * feats[k] for k in keys)
                err = y_hat - y
                intercept -= lr * err
                for k in keys:
                    coef[k] -= lr * err * feats[k]
        return CausalModel(coefficients=coef, intercept=intercept)

    def predict(self, model: CausalModel, x: float) -> float:
        feats = self._features(x)
        return model.intercept + sum(model.coefficients.get(k, 0.0) * v for k, v in feats.items())


# ---- Quantum-inspired engine (Monte Carlo collapse) ----
class QuantumEngine:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg

    def collapse(self, scores: List[float]) -> int:
        # Treat scores as amplitudes; sample index via softmax temperature
        if not scores:
            return 0
        temp = max(1e-6, self.cfg.quantum_temperature)
        mx = max(scores)
        weights = [pow(2.718281828, (s - mx) / temp) for s in scores]
        total = sum(weights) or 1.0
        probs = [w / total for w in weights]
        r = random.random()
        acc = 0.0
        for i, p in enumerate(probs):
            acc += p
            if r <= acc:
                return i
        return len(scores) - 1


# ---- Minimal HDL DSL and simulator ----
@dataclass
class HDLCircuit:
    width: int
    taps: Tuple[int, int]
    state: int


class HDLSim:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg

    def compile_from_tokens(self, tokens: list[str]) -> HDLCircuit:
        # Build a tiny LFSR from token hash for determinism
        seed = 0
        for t in tokens:
            seed ^= (hash(t) & 0xFFFF)
        width = max(4, min(16, (len(tokens) % 12) + 4))
        # Pick taps based on seed
        a = (seed % (width - 1)) + 1
        b = ((seed >> 3) % (width - 1)) + 1
        if a == b:
            b = (b % (width - 1)) + 1
        state = (seed or 1) & ((1 << width) - 1)
        return HDLCircuit(width=width, taps=(a, b), state=state)

    def step(self, c: HDLCircuit, inp_bit: int = 1) -> int:
        # 1-bit feedback LFSR with optional input mixing
        a, b = c.taps
        bit_a = (c.state >> (a - 1)) & 1
        bit_b = (c.state >> (b - 1)) & 1
        fb = bit_a ^ bit_b ^ (inp_bit & 1)
        c.state = ((c.state << 1) | fb) & ((1 << c.width) - 1)
        out = c.state & 1
        return out

    def simulate(self, circ: HDLCircuit, steps: int = 32) -> dict[str, float]:
        ones = 0
        toggles = 0
        last = (circ.state & 1)
        for i in range(steps):
            o = self.step(circ, 1)
            ones += o
            if o != last:
                toggles += 1
            last = o
        bias = ones / max(1, steps)
        stability = 1.0 - (toggles / max(1, steps))
        return {"bias": bias, "stability": stability}


# ---- Ethics & invariance engine ----
class EthicsEngine:
    def __init__(self):
        self.qa_log: list[dict[str, str]] = []

    @staticmethod
    def _has_conflict(tokens: set[str]) -> bool:
        return ("allow" in tokens and "deny" in tokens) or ("enable" in tokens and "disable" in tokens)

    def verify_axioms(self, axioms: list[str]) -> tuple[bool, list[str]]:
        tokens = set(" ".join(axioms).split())
        issues: list[str] = []
        if self._has_conflict(tokens):
            issues.append("conflict: allow vs deny or enable vs disable detected")
        if any(len(a.split()) > 40 for a in axioms):
            issues.append("overbroad axiom: too many tokens reduces clarity")
        ok = len(issues) == 0
        # Socratic loop (internal Q/A)
        questions = [
            "Could these axioms incentivize unsafe behavior?",
            "Do any axioms remove required safety checks?",
            "Are constraints consistent across variants?",
        ]
        for q in questions:
            a = "no" if ok else "possibly"
            self.qa_log.append({"q": q, "a": a})
        return ok, issues


# ---- Federated knowledge exchange ----
class Federation:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg

    def exchange(self, rules: list[str]) -> list[str]:
        # Simulate receiving rules from peer nodes by perturbing tokens
        rnd = random.Random(len(rules) + self.cfg.seed)
        peers = []
        for _ in range(self.cfg.federation_nodes):
            for r in rules[: max(1, len(rules) // 2)]:
                parts = r.split()
                if parts and rnd.random() < 0.3:
                    parts.append(rnd.choice(["peer", "consensus", "verified"]))
                peers.append(" ".join(parts))
        # Deduplicate
        return sorted(set(peers))

class Orchestrator:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.kg = KnowledgeGraph(cfg)
        self.rsl = RSL(cfg)
        self.checks = Checks()
        self.ledger = Ledger(cfg)
        self.causal = CausalModeler(cfg)
        self.quantum = QuantumEngine(cfg)
        self.hdl = HDLSim(cfg)
        self.ethics = EthicsEngine()
        self.federation = Federation(cfg)
        self.history: List[Dict[str, Any]] = []
        self.best_meta: float = 0.0

    def seed(self) -> None:
        random.seed(self.cfg.seed)
        self.kg.add_rule("declare_intent before external_call", weight=1.0, seed=42)
        self.kg.add_rule("verify_patch_proof before commit", weight=1.2, seed=43)
        self.kg.add_rule("compress_redundant_rules", weight=0.8, seed=44)

    def run(self) -> None:
        self.seed()
        stable_snapshot = self.kg.snapshot()
        last_best_score = 0.0
        xs: List[float] = []
        ys: List[float] = []
        patience = 0
        for it in range(self.cfg.iterations):
            # Adaptive planning: if scores plateau, reduce iterations for self-improvement; else, explore more
            base_axioms = [r.pattern for r in self.kg.all_rules()]
            variants = self.rsl.propose_variants(base_axioms, n=self.cfg.variants_per_round)
            # Ethics gate pre-evaluation
            ok, issues = self.ethics.verify_axioms(base_axioms)
            if not ok:
                self.ledger.append({"event": "ethics_block", "issues": issues, "iteration": it})
                # soften by trimming conflicting terms and continue
                base_axioms = [
                    " ".join(w for w in ax.split() if w not in {"allow", "deny", "enable", "disable"})
                    for ax in base_axioms
                ]
                variants = self.rsl.propose_variants(base_axioms, n=self.cfg.variants_per_round)

            # Federated exchange: enrich ruleset from peers and feed back as axioms
            peer_rules = self.federation.exchange([r.pattern for r in self.kg.all_rules()])
            base_axioms = base_axioms + peer_rules[: max(0, 4 - (len(base_axioms) % 4))]
            evald = self.rsl.evaluate_variants(variants, steps=self.cfg.sim_steps, topk=self.cfg.topk_variants)

            # Optional quantum collapse to pick a champion among top
            if self.cfg.enable_quantum:
                idx = self.quantum.collapse([t["score_adj"] for t in evald])
                top = evald[:]
                # Move chosen to front to influence materialization
                if 0 <= idx < len(top):
                    top.insert(0, top.pop(idx))
            else:
                top = evald

            materialized: List[str] = []
            for t in top:
                # materialize only a subset
                for ax in t["variant"]["axioms"][:2]:
                    r = self.kg.add_rule(ax, weight=1.0 + t["sim"]["score"] / 10.0, seed=t["variant"]["seed"])
                    materialized.append(r.id)

            # Hardware co-design: compile and simulate a tiny circuit from axiom tokens
            circ = self.hdl.compile_from_tokens(list(set(" ".join(base_axioms).split())))
            hdl_metrics = self.hdl.simulate(circ, steps=self.cfg.hdl_sim_steps)

            # Targeted improvement: if compression has plateaued, emphasize checks
            comp = self.kg.compress(threshold=self.cfg.compress_threshold, levels=self.cfg.hierarchical_levels)
            checks_info = self.checks.strengthen_checks([r.pattern for r in self.kg.all_rules()])

            # Simple adaptive iteration logic based on score improvements
            best_score = max((t["sim"]["score"] for t in top), default=0.0)
            xs.append(float(it))
            ys.append(best_score)
            if best_score < last_best_score * 0.98:  # regression beyond noise
                if self.cfg.rollback_on_regression:
                    self.kg.restore(stable_snapshot)
            else:
                stable_snapshot = self.kg.snapshot()
                last_best_score = best_score

            # Fit causal model periodically and forecast next improvement
            causal_info: Dict[str, Any] = {}
            if len(xs) >= 3 and len(set(xs)) == len(xs):
                model = self.causal.fit(xs[-min(10, len(xs)):], ys[-min(10, len(ys)):])
                forecast = self.causal.predict(model, float(it + 1))
                causal_info = {"coefficients": model.coefficients, "intercept": model.intercept, "forecast": forecast}

            # Monitoring & convergence heuristic (meta-score proxy)
            meta = (best_score * 0.5) + (comp.get("efficiency_score", 0.0) * 0.5)
            if meta <= self.best_meta * 0.995:  # little improvement
                patience += 1
            else:
                patience = 0
                self.best_meta = max(self.best_meta, meta)

            entry = {
                "iteration": it,
                "top_variants": [{"seed": t["variant"]["seed"], "score": t["sim"]["score"]} for t in top],
                "materialized_rules": materialized,
                "compression": comp,
                "checks": checks_info[:5],  # preview
                "kg_size": len(self.kg.all_rules()),
                "diversity": getattr(self.rsl, "last_diversity", 0.0),
                "causal": causal_info,
                "hdl": hdl_metrics,
                "ethics": {"issues": issues if not ok else []},
                "meta": meta,
                "patience": patience,
            }
            self.ledger.append(entry)

            if patience >= self.cfg.monitor_patience:
                self.ledger.append({"event": "early_converged", "iteration": it, "meta": meta})
                break

        # Final summary entry
        agg = self.ledger.aggregate_metrics()
        anomalies = self.ledger.detect_anomalies()
        merkle = self.ledger.merkle_root()
        self.ledger.append({"summary": agg, "anomalies": anomalies, "merkle_root": merkle})
