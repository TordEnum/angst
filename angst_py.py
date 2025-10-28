#!/usr/bin/env python3
"""
Angst Orchestrator (Python): KG + Spec + CLI
- Uses C++ binary for PHRE/RSL simulation scoring
- Uses Rust binary for sandboxed code/test execution

Build the native tools first:
  g++ -O2 -std=c++17 -o angst_sim angst_sim.cpp
  rustc -O angst_sandbox.rs -o angst_sandbox

Run:
  python3 angst_py.py run --prompt "Create a function that reverses a string." \
    --sim ./angst_sim --sandbox ./angst_sandbox --auto-approve
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import random
import re
import statistics
import subprocess
import tempfile
import textwrap
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


# =====================
# Config
# =====================


@dataclass
class Config:
    iterations: int = 4
    topk_variants: int = 4
    variants_per_round: int = 12
    sim_steps: int = 50
    compress_threshold: float = 0.6
    hierarchical_levels: int = 3
    exploration_epsilon: float = 0.2
    exploitation_weight: float = 0.7
    out_dir: str = "out_angst_python"
    allow_auto_approve: bool = True

    # Native tools
    sim_bin: str = "./angst_sim"
    sandbox_bin: str = "./angst_sandbox"


DEFAULT_CONFIG = Config()


# =====================
# Utilities
# =====================


def stable_hash(*parts: str, length: int = 12) -> str:
    import hashlib
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode())
        h.update(b"|")
    return h.hexdigest()[:length]


# =====================
# Ledger (lightweight)
# =====================


class Ledger:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.root = Path(cfg.out_dir)
        self.root.mkdir(parents=True, exist_ok=True)
        self.path = self.root / "ledger_py.jsonl"

    def append(self, entry: Dict[str, Any]) -> None:
        entry = dict(entry)
        entry["ts"] = time.time()
        with open(self.path, "a", encoding="utf8") as f:
            f.write(json.dumps(entry, default=str) + "\n")


# =====================
# Knowledge Graph
# =====================


@dataclass
class Rule:
    id: str
    pattern: str
    weight: float


class KnowledgeGraph:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.rules: Dict[str, Rule] = {}
        self._add_counter = 0

    def add_rule(self, pattern: str, weight: float = 1.0, seed: Optional[int] = None) -> Rule:
        pat = self._normalize(pattern)
        self._add_counter += 1
        rid = stable_hash(pat, str(seed or 0), str(self._add_counter))
        r = Rule(id=rid, pattern=pat, weight=float(weight))
        self.rules[rid] = r
        return r

    def _normalize(self, pattern: str) -> str:
        parts = [p for p in re.split(r"\s+", (pattern or "").strip().lower()) if p]
        return " ".join(sorted(parts))

    def all_rules(self) -> List[Rule]:
        return list(self.rules.values())

    def _jaccard(self, a: Set[str], b: Set[str]) -> float:
        return len(a & b) / len(a | b) if a and b else 0.0

    def _merge(self, a: str, b: str) -> str:
        return " ".join(sorted(set(a.split()) | set(b.split())))

    def compress(self, threshold: float | None = None, levels: int | None = None) -> Dict[str, Any]:
        thr = threshold if threshold is not None else self.cfg.compress_threshold
        max_levels = levels if levels is not None else self.cfg.hierarchical_levels
        removed: List[str] = []
        for _ in range(max_levels):
            keys = sorted(self.rules.keys(), key=lambda k: (self.rules[k].weight, self.rules[k].pattern, k))
            changed = False
            for i in range(len(keys)):
                ra = self.rules.get(keys[i])
                if not ra:
                    continue
                sa = set(ra.pattern.split())
                for j in range(i + 1, len(keys)):
                    rb = self.rules.get(keys[j])
                    if not rb:
                        continue
                    sb = set(rb.pattern.split())
                    if self._jaccard(sa, sb) >= thr:
                        dst, src = (rb, ra)
                        if (ra.weight > rb.weight) or (ra.weight == rb.weight and ra.id < rb.id):
                            dst, src = (ra, rb)
                        dst.pattern = self._merge(dst.pattern, src.pattern)
                        dst.weight = max(dst.weight, src.weight) + 0.1
                        self.rules.pop(src.id, None)
                        removed.append(src.id)
                        changed = True
            if not changed:
                break
        return {"removed": removed, "final_count": len(self.rules)}


# =====================
# Semantic Extractor
# =====================


@dataclass
class FunctionSpec:
    name: str
    args: List[Tuple[str, str]]
    returns: str


@dataclass
class RequirementsSpec:
    intent: str
    functions: List[FunctionSpec]


class SemanticExtractor:
    @staticmethod
    def parse(prompt: str) -> RequirementsSpec:
        t = (prompt or "").strip().lower()
        fns: List[FunctionSpec] = []
        if "reverse" in t:
            fns.append(FunctionSpec("reverse_string", [("s", "str")], "str"))
        if not fns:
            fns.append(FunctionSpec("generated", [("x", "int")], "int"))
        return RequirementsSpec(intent=prompt.strip(), functions=fns)

    @staticmethod
    def to_axioms(spec: RequirementsSpec) -> List[str]:
        axioms = [f"intent {spec.intent}"]
        for f in spec.functions:
            sig = ",".join(f"{n}:{t}" for n, t in f.args)
            axioms.append(f"fn {f.name}({sig})->{f.returns}")
        return axioms


# =====================
# Variant proposal + simulation (via C++)
# =====================


class RSL:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        random.seed(42)

    def propose(self, base_axioms: List[str], n: Optional[int] = None) -> List[Dict[str, Any]]:
        n = n or self.cfg.variants_per_round
        base = base_axioms or ["act safe", "declare intent"]
        out: List[Dict[str, Any]] = []
        for _ in range(n):
            seed = random.randint(1, 1 << 30)
            rnd = random.Random(seed)
            mutated: List[str] = []
            for p in base:
                parts = p.split()
                if rnd.random() < 0.35:
                    parts.append(rnd.choice(["fast", "safe", "verify", "compress", "stronger"]))
                mutated.append(" ".join(parts))
            out.append({"seed": seed, "axioms": mutated})
        return out

    def _avg_axiom_len(self, axioms: List[str]) -> float:
        toks = " ".join(axioms).split()
        return float(len(" ".join(axioms))) / max(1, len(axioms))

    def evaluate_cpp(self, variants: List[Dict[str, Any]], steps: int, sim_bin: str) -> List[Dict[str, Any]]:
        # Write a simple TSV for C++: seed steps avg_axiom_len
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            for v in variants:
                avg_len = self._avg_axiom_len(v["axioms"]) if v["axioms"] else 1.0
                tmp.write(f"{v['seed']}\t{steps}\t{avg_len:.6f}\n")
            tmp_path = tmp.name
        try:
            proc = subprocess.run([sim_bin, "--input", tmp_path], check=True, text=True, capture_output=True)
            scores: Dict[int, float] = {}
            for line in proc.stdout.splitlines():
                if not line.strip():
                    continue
                parts = line.strip().split()
                if len(parts) >= 2:
                    try:
                        seed = int(parts[0]); score = float(parts[1])
                        scores[seed] = score
                    except Exception:
                        continue
            results = []
            for v in variants:
                s = scores.get(v["seed"], 0.0)
                results.append({"variant": v, "sim": {"seed": v["seed"], "score": s}})
            # Compute score_adj similar to python version
            for r in results:
                r["score_adj"] = r["sim"]["score"] * self.cfg.exploitation_weight + random.random() * self.cfg.exploration_epsilon
            results.sort(key=lambda x: x["score_adj"], reverse=True)
            return results
        finally:
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


# =====================
# Code synthesis + tests + rust sandbox
# =====================


class Synth:
    @staticmethod
    def make_code(prompt: str) -> str:
        if "reverse" in prompt.lower():
            return textwrap.dedent(
                """
                def reverse_string(s: str) -> str:
                    return s[::-1]
                """
            )
        return "\n"

    @staticmethod
    def make_tests(prompt: str, code: str) -> List[str]:
        tests: List[str] = []
        if "reverse" in prompt.lower():
            tests.append(textwrap.dedent(
                """
                def run():
                    assert reverse_string("") == ""
                    assert reverse_string("abc") == "cba"
                """
            ))
        if code.strip():
            tests.append("""\n                def run():
                    _ = 1
            """)
        return tests


class RustSandbox:
    def __init__(self, bin_path: str):
        self.bin_path = bin_path

    def run(self, code: str, tests: List[str], timeout: int = 3, stdout_cap: int = 200000) -> Dict[str, Any]:
        with tempfile.TemporaryDirectory(prefix="angst_sbx_py_") as tmp:
            code_path = Path(tmp) / "code.py"
            tests_path = Path(tmp) / "tests.json"
            code_path.write_text(code, encoding="utf8")
            tests_path.write_text(json.dumps(tests), encoding="utf8")
            proc = subprocess.run(
                [self.bin_path, "--code-file", str(code_path), "--tests-file", str(tests_path), "--timeout", str(timeout), "--stdout-cap", str(stdout_cap)],
                text=True,
                capture_output=True,
            )
            if proc.returncode != 0:
                return {"ok": False, "stderr": proc.stderr[:1000]}
            try:
                return json.loads(proc.stdout.strip().splitlines()[-1])
            except Exception as e:
                return {"ok": False, "error": f"bad_json:{e}", "raw": proc.stdout[-500:]}


# =====================
# Orchestrator
# =====================


class Orchestrator:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.kg = KnowledgeGraph(cfg)
        self.rsl = RSL(cfg)
        self.ledger = Ledger(cfg)
        self.sandbox = RustSandbox(cfg.sandbox_bin)

    def seed(self) -> None:
        self.kg.add_rule("declare_intent before external_call", weight=1.0, seed=42)
        self.kg.add_rule("verify_patch_proof before commit", weight=1.2, seed=43)
        self.kg.add_rule("compress_redundant_rules", weight=0.8, seed=44)

    def run_once(self, prompt: str, sim_bin: str) -> Dict[str, Any]:
        spec = SemanticExtractor.parse(prompt)
        axioms = SemanticExtractor.to_axioms(spec)
        base_axioms = [r.pattern for r in self.kg.all_rules()] + axioms
        variants = self.rsl.propose(base_axioms, n=self.cfg.variants_per_round)
        sims = self.rsl.evaluate_cpp(variants, steps=self.cfg.sim_steps, sim_bin=sim_bin)
        top = sorted(sims, key=lambda x: x["score_adj"], reverse=True)[: self.cfg.topk_variants]

        # Synthesize code for the prompt and test via Rust sandbox
        code = Synth.make_code(prompt)
        tests = Synth.make_tests(prompt, code)
        sbx = self.sandbox.run(code, tests)

        mat_ids: List[str] = []
        if (sbx or {}).get("ok") and (sbx.get("tests", {}).get("failed", 1) == 0):
            for t in top:
                for ax in t["variant"]["axioms"][:2]:
                    r = self.kg.add_rule(ax, weight=1.0 + t["sim"]["score"] / 10.0, seed=t["variant"]["seed"])
                    mat_ids.append(r.id)

        comp = self.kg.compress()
        entry = {
            "prompt": prompt,
            "top_variants": [
                {"seed": t["variant"]["seed"], "score": t["sim"]["score"], "axioms": t["variant"]["axioms"]}
                for t in top
            ],
            "sandbox": sbx,
            "materialized_rules": mat_ids,
            "compression": comp,
            "kg_size": len(self.kg.all_rules()),
        }
        self.ledger.append(entry)
        return entry


# =====================
# CLI
# =====================


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Angst Orchestrator (Python)")
    ap.add_argument("cmd", choices=["once", "run"], help="Run once or multi-iter loop")
    ap.add_argument("--prompt", type=str, required=False, default="Create a function that reverses a string.")
    ap.add_argument("--sim", type=str, required=False, default=DEFAULT_CONFIG.sim_bin)
    ap.add_argument("--sandbox", type=str, required=False, default=DEFAULT_CONFIG.sandbox_bin)
    ap.add_argument("--auto-approve", action="store_true")
    args = ap.parse_args(argv)

    cfg = dataclasses.replace(DEFAULT_CONFIG, allow_auto_approve=bool(args.auto_approve), sim_bin=args.sim, sandbox_bin=args.sandbox)

    orch = Orchestrator(cfg)
    orch.seed()
    if args.cmd == "once":
        out = orch.run_once(args.prompt, sim_bin=cfg.sim_bin)
        print(json.dumps(out, indent=2))
    else:
        last = None
        for _ in range(cfg.iterations):
            last = orch.run_once(args.prompt, sim_bin=cfg.sim_bin)
        print(json.dumps({"summary": {"last_kg_size": last.get("kg_size") if last else 0}}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
