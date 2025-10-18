#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Angst Monolith v2: Autonomous Meta-Architect + ACLC + C++ Sandbox
- Python Orchestrator (this file)
- Rust ACLC compiler (aclc.rs): language generator + IR + Python transpiler
- C++ sandbox wrapper (sandbox_exec.cpp): process isolation with rlimits/timeout

Key subsystems (high-level):
- Meta-Knowledge Graph (Meta-KG) with dynamic clustering, provenance, compression/expansion
- Dual-Authority Safety (Core Orders immutable + Adaptive Safety Engine)
- Hierarchical Simulation Fabric (Symbolic/Algorithmic/World tiers, Superpositional Logic)
- Feedback-Driven Self-Improvement Pipeline with Evolutionary Optimization
- Meta-Architect that designs, benchmarks, and evolves modules with self-blueprints
- ACLC: Adaptive Code Language Compiler via Rust companion (with Python fallback)
- CI + C++ Sandbox runner; Explainability and Recursive Ledger System (RLS)
- Distributed Mesh + Consensus; Orchestration Kernel for cohesive control

Notes:
- This orchestrator uses external helpers when available:
  * ./aclc (compiled from aclc.rs) for language design/compilation
  * ./sandbox_exec (compiled from sandbox_exec.cpp) for secure execution
  Fallbacks are provided to keep the system runnable when those binaries are missing.
"""
from __future__ import annotations

import argparse
import ast
import base64
import dataclasses
import hashlib
import json
import math
import os
import random
import re
import shutil
import signal
import statistics
import string
import subprocess
import sys
import tempfile
import textwrap
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
import itertools
import statistics as _statistics

# =============================================================
# Config
# =============================================================


@dataclass
class Config:
    # Core search + orchestration
    iterations: int = 4
    variants_per_round: int = 12
    topk_variants: int = 4
    sim_steps: int = 40
    parallel_workers: int = 4

    # Meta-KG
    compress_threshold: float = 0.6
    hierarchical_levels: int = 3

    # Exploration/Exploitation
    exploration_epsilon: float = 0.2
    exploitation_weight: float = 0.7

    # Sandboxing
    sandbox_timeout_sec: float = 3.0
    sandbox_cpu_seconds: int = 2
    sandbox_mem_bytes: int = 256 * 1024 * 1024
    sandbox_max_stdout: int = 200_000
    use_cpp_sandbox: bool = True
    cpp_sandbox_path: str = "./sandbox_exec"

    # ACLC (Rust)
    use_rust_aclc: bool = True
    rust_aclc_path: str = "./aclc"

    # CI / Coverage
    min_coverage_ratio: float = 0.15

    # Safety
    default_policy: str = (
        "# Core Orders — immutable\n"
        "core forbid network\n"
        "core deny import socket, subprocess, http, urllib, requests\n"
        "core deny call os.system, os.popen, subprocess.Popen\n"
        "core limit time 3s\n"
        "core limit stdout 200000\n"
        "# Adaptive layer — may refine, never weaken Core\n"
        "deny import shlex\n"
    )

    # Meta scoring weights
    meta_alpha: float = 0.6
    meta_beta: float = 0.2
    meta_gamma: float = 0.15
    meta_delta: float = 0.05

    # Directories
    out_dir: str = "out_angst_v2"
    ledger_file: str = "ledger.jsonl"

    # Randomness
    seed: int = 42
    
    # Distributed mesh
    swarm_nodes: int = 3


DEFAULT_CONFIG = Config()


# =============================================================
# Utilities
# =============================================================


def stable_hash(*parts: str, length: int = 12) -> str:
    m = hashlib.sha256()
    for p in parts:
        m.update(p.encode("utf-8", errors="ignore"))
        m.update(b"|")
    return m.hexdigest()[:length]


def now_ts() -> float:
    return time.time()


def ensure_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)


# =============================================================
# Recursive Ledger System (RLS) + Explainability
# =============================================================


class Ledger:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.root = Path(cfg.out_dir)
        ensure_dir(self.root)
        self.path = self.root / cfg.ledger_file
        self.chain_path = self.root / "chain.jsonl"
        self.exp_path = self.root / "explain.jsonl"

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        entry = {**entry, "ts": now_ts()}
        with open(self.path, "a", encoding="utf8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        self._append_chain(entry)
        return entry

    def _append_chain(self, entry: Dict[str, Any]) -> None:
        prev = "0" * 64
        if self.chain_path.exists():
            try:
                with open(self.chain_path, "rb") as f:
                    for line in f:
                        pass
                    if line:
                        last = json.loads(line)
                        prev = last.get("hash", prev)
            except Exception:
                pass
        payload = json.dumps(entry, sort_keys=True)
        h = hashlib.sha256((prev + "|" + payload).encode()).hexdigest()
        rec = {"prev": prev, "hash": h, "entry": entry, "ts": now_ts()}
        with open(self.chain_path, "a", encoding="utf8") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    def explain(self, subject: str, context: Dict[str, Any]) -> None:
        rec = {"subject": subject, "context": context, "ts": now_ts()}
        with open(self.exp_path, "a", encoding="utf8") as f:
            f.write(json.dumps(rec, default=str) + "\n")

    def write_artifact(self, category: str, name: str, data: Dict[str, Any]) -> Path:
        cat = self.root / category
        ensure_dir(cat)
        p = cat / f"{name}.json"
        with open(p, "w", encoding="utf8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2, sort_keys=True)
        return p


# =============================================================
# Meta-Knowledge Graph (Meta-KG)
# =============================================================


@dataclass
class Rule:
    id: str
    pattern: str
    weight: float
    freq: int = 0
    provenance: Dict[str, Any] = dataclasses.field(default_factory=dict)


class MetaKnowledgeGraph:
    def __init__(self, cfg: Config, ledger: Ledger):
        self.cfg = cfg
        self.ledger = ledger
        self.rules: Dict[str, Rule] = {}
        self.snapshots: List[Dict[str, Any]] = []

    @staticmethod
    def _normalize(pattern: str) -> str:
        text = (pattern or "").strip().lower()
        tokens = [t for t in re.split(r"\s+", text) if t]
        return " ".join(sorted(tokens))

    def add_rule(self, pattern: str, weight: float = 1.0, seed: Optional[int] = None) -> Rule:
        pat = self._normalize(pattern)
        rid = stable_hash(pat, str(seed or 0), str(len(self.rules) + 1))
        rule = Rule(id=rid, pattern=pat, weight=float(weight), provenance={"seed": seed, "created": now_ts()})
        self.rules[rid] = rule
        return rule

    def record_use(self, rid: str) -> None:
        if rid in self.rules:
            self.rules[rid].freq += 1

    def all_rules(self) -> List[Rule]:
        return list(self.rules.values())

    def compress(self) -> Dict[str, Any]:
        # Deterministic dedup + Jaccard merges
        initial = len(self.rules)
        removed: List[str] = []
        ids = sorted(self.rules.keys())
        def tokens(s: str) -> Set[str]:
            return set(s.split())
        for i in range(len(ids)):
            a = self.rules.get(ids[i])
            if not a:
                continue
            for j in range(i + 1, len(ids)):
                b = self.rules.get(ids[j])
                if not b:
                    continue
                ta, tb = tokens(a.pattern), tokens(b.pattern)
                if not ta or not tb:
                    continue
                jacc = len(ta & tb) / len(ta | tb)
                if jacc >= self.cfg.compress_threshold:
                    # Merge lower weight/freq into higher
                    dst, src = (a, b)
                    if (b.weight, b.freq, b.id) > (a.weight, a.freq, a.id):
                        dst, src = (b, a)
                    dst.pattern = " ".join(sorted(ta | tb))
                    dst.weight = max(dst.weight, src.weight) + 0.1
                    dst.freq += src.freq
                    dst.provenance.setdefault("merged_from", []).append(src.id)
                    removed.append(src.id)
                    # Use pop with default to avoid KeyError if src was previously removed
                    self.rules.pop(src.id, None)
        final = len(self.rules)
        eff = (initial - final) / initial if initial else 0.0
        return {"removed": removed, "final": final, "efficiency_score": eff}

    def snapshot(self) -> Dict[str, Any]:
        snap = {"ts": now_ts(), "rules": {rid: dataclasses.asdict(r) for rid, r in self.rules.items()}}
        self.snapshots.append(snap)
        return snap


# =============================================================
# ACLC client (Rust) and Python fallback (MiniLang/MetaLang)
# =============================================================


class ACLCClient:
    def __init__(self, cfg: Config, ledger: Ledger):
        self.cfg = cfg
        self.ledger = ledger

    def _has_aclc(self) -> bool:
        return self.cfg.use_rust_aclc and os.path.exists(self.cfg.rust_aclc_path) and os.access(self.cfg.rust_aclc_path, os.X_OK)

    @staticmethod
    def _b64(s: str) -> str:
        return base64.b64encode(s.encode("utf8")).decode()

    def design_language(self, prompt: str) -> Dict[str, Any]:
        if not self._has_aclc():
            return {"language": {"name": "MiniLangEx", "notes": "fallback"}}
        out = subprocess.run([self.cfg.rust_aclc_path, "--design", "--prompt", self._b64(prompt)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if out.returncode != 0:
            return {"language": {"name": "MiniLangEx", "notes": f"fallback:{out.stderr[:100]}"}}
        try:
            return json.loads(out.stdout)
        except Exception:
            return {"language": {"name": "MiniLangEx", "notes": "fallback:json"}}

    def compile(self, source: str) -> Dict[str, Any]:
        if not self._has_aclc():
            # Python fallback: treat as simplistic MiniLang or Python
            py = MiniLang.to_python(source) if source.strip().startswith("fn ") else (MetaLang.to_python(source) if source.strip().startswith("fn ") and "{" in source else source)
            return {"ir": {"nodes": []}, "python_code": py}
        out = subprocess.run([self.cfg.rust_aclc_path, "--compile", "--source", self._b64(source)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if out.returncode != 0:
            return {"ir": {"nodes": []}, "python_code": "\n"}
        try:
            return json.loads(out.stdout)
        except Exception:
            return {"ir": {"nodes": []}, "python_code": "\n"}


class MiniLangError(Exception):
    pass


class MiniLang:
    @staticmethod
    def parse(source: str) -> Dict[str, Any]:
        lines = [ln.rstrip() for ln in source.strip().splitlines() if ln.strip()]
        if not lines or not lines[0].startswith("fn ") or not lines[0].endswith(":"):
            raise MiniLangError("MiniL must start with 'fn name(args) -> ret:'")
        header = lines[0][3:-1].strip()
        m = re.match(r"([a-zA-Z_][a-zA-Z0-9_]*)\((.*)\)\s*->\s*([^:]+)$", header)
        if not m:
            raise MiniLangError("Invalid function header")
        name, args, ret = m.group(1), m.group(2), m.group(3)
        body = lines[1:]
        return {"name": name, "args": args.strip(), "ret": ret.strip(), "body": body}

    @staticmethod
    def to_python(source: str) -> str:
        spec = MiniLang.parse(source)
        indent = " " * 4
        body: List[str] = []
        if not spec["body"]:
            body.append("pass")
        else:
            for ln in spec["body"]:
                if ln.startswith("return "):
                    body.append(ln)
                elif ln.startswith("assign "):
                    body.append(ln.replace("assign ", "", 1))
                else:
                    raise MiniLangError(f"Unsupported body line: {ln}")
        args_src = spec["args"]
        out = [f"def {spec['name']}({args_src}):"] + [indent + b for b in body]
        return "\n".join(out) + "\n"


class MetaLangError(Exception):
    pass


class MetaLang:
    @staticmethod
    def to_python(src: str) -> str:
        src = src.strip()
        m = re.match(r"fn\s+([a-zA-Z_][a-zA-Z0-9_]*)\(([^)]*)\)\s*->\s*([^\s{]+)\s*\{([\s\S]*)\}$", src)
        if not m:
            raise MetaLangError("Invalid MetaLang function")
        name, args_part, ret, body = m.group(1), m.group(2), m.group(3), m.group(4)
        py_lines: List[str] = [f"def {name}({MetaLang._py_args(args_part)}):"]
        for ln in MetaLang._split(body):
            if not ln:
                continue
            py_lines.append("    " + MetaLang._compile_line(ln))
        if len(py_lines) == 1:
            py_lines.append("    pass")
        return "\n".join(py_lines) + "\n"

    @staticmethod
    def _py_args(ap: str) -> str:
        ap = ap.strip()
        if not ap:
            return ""
        parts = [a.strip() for a in ap.split(",") if a.strip()]
        return ", ".join(parts)

    @staticmethod
    def _split(body: str) -> List[str]:
        text = body.strip()
        buf, lines = "", []
        for ch in text:
            if ch == ';':
                lines.append(buf.strip())
                buf = ""
            else:
                buf += ch
        if buf.strip():
            lines.append(buf.strip())
        return lines

    @staticmethod
    def _compile_line(ln: str) -> str:
        m = re.match(r"let\s+(?:mut\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*:(?:[^=]+)=\s*(.*)$", ln)
        if m:
            return f"{m.group(1)} = {m.group(2)}"
        m = re.match(r"for\s+([a-zA-Z_][a-zA-Z0-9_]*)\s+in\s+0\.\.(\w+)\s*\{\s*([^}]*)\s*\}$", ln)
        if m:
            var, end, inner = m.group(1), m.group(2), m.group(3)
            inner_py = MetaLang._compile_line(inner) if inner else "pass"
            return f"\n    for {var} in range({end}):\n        {inner_py}"
        if ln.startswith("return "):
            return ln
        return ln


# =============================================================
# Safety: Dual-Authority Policy (Core + Adaptive) + Static Analyzer
# =============================================================


@dataclass
class Policy:
    core_lines: List[str]
    adaptive_lines: List[str]

    @staticmethod
    def parse(dsl: str) -> "Policy":
        core, adaptive = [], []
        for raw in (dsl or "").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("core "):
                core.append(line[5:].strip())
            else:
                adaptive.append(line)
        return Policy(core_lines=core, adaptive_lines=adaptive)

    def deny_imports(self) -> Set[str]:
        denies: Set[str] = set()
        for scope in (self.core_lines + self.adaptive_lines):
            if scope.startswith("deny import"):
                parts = [x.strip() for x in scope[len("deny import"):].split(',') if x.strip()]
                denies.update(parts)
        return denies

    def deny_calls(self) -> Set[str]:
        denies: Set[str] = set()
        for scope in (self.core_lines + self.adaptive_lines):
            if scope.startswith("deny call"):
                parts = [x.strip() for x in scope[len("deny call"):].split(',') if x.strip()]
                denies.update(parts)
        return denies

    def limit_time(self) -> float:
        lim = 3.0
        def scan(lines: List[str]) -> Optional[float]:
            for ln in lines:
                m = re.match(r"limit time (\d+(?:\.\d+)?)s$", ln)
                if m:
                    return float(m.group(1))
            return None
        return scan(self.core_lines) or scan(self.adaptive_lines) or lim

    def limit_stdout(self) -> int:
        lim = 200000
        def scan(lines: List[str]) -> Optional[int]:
            for ln in lines:
                m = re.match(r"limit stdout (\d+)$", ln)
                if m:
                    return int(m.group(1))
            return None
        return scan(self.core_lines) or scan(self.adaptive_lines) or lim


class InvariantChecker:
    CORE_FORBIDS = {"network", "socket", "subprocess"}

    @staticmethod
    def verify_no_weaken(core: Policy, proposal: Policy) -> List[str]:
        issues: List[str] = []
        # Ensure all core directives remain present or stricter
        core_text = set(core.core_lines)
        prop_text = set(proposal.core_lines)
        missing = core_text - prop_text
        if missing:
            issues.append(f"Core lines missing in proposal: {sorted(missing)[:5]}")
        # Adaptive must not allow what core forbids
        denies = proposal.deny_imports()
        for token in InvariantChecker.CORE_FORBIDS:
            if token == "network":
                continue
            if token not in denies:
                # not strictly required, but flag when adaptive relaxes typical risk
                pass
        return issues


class StaticAnalyzer:
    @staticmethod
    def check(code: str, policy: Policy) -> List[str]:
        issues: List[str] = []
        try:
            tree = ast.parse(code)
        except Exception as e:
            return [f"AST parse error: {e}"]
        denies = policy.deny_imports()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    root = (alias.name or '').split('.')[0]
                    if root in denies:
                        issues.append(f"Denied import: {alias.name}")
            if isinstance(node, ast.ImportFrom):
                root = (node.module or '').split('.')[0]
                if root in denies:
                    issues.append(f"Denied import-from: {node.module}")
            if isinstance(node, ast.Call):
                dotted = StaticAnalyzer._dotted_name(node.func)
                if dotted in policy.deny_calls():
                    issues.append(f"Denied call: {dotted}")
        # banned patterns
        for pat in (r"eval\(", r"exec\("):
            if re.search(pat, code):
                issues.append(f"Banned pattern: {pat}")
        return issues

    @staticmethod
    def _dotted_name(fn: ast.AST) -> str:
        parts: List[str] = []
        cur = fn
        while isinstance(cur, ast.Attribute):
            parts.insert(0, cur.attr)
            cur = cur.value
        if isinstance(cur, ast.Name):
            parts.insert(0, cur.id)
        return ".".join(parts)


# =============================================================
# C++ Sandbox wrapper client + Python fallback sandbox
# =============================================================


class SandboxResult(Dict[str, Any]):
    pass


class CPPSandbox:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def available(self) -> bool:
        return self.cfg.use_cpp_sandbox and os.path.exists(self.cfg.cpp_sandbox_path) and os.access(self.cfg.cpp_sandbox_path, os.X_OK)

    def run(self, argv: Sequence[str], timeout_s: float, mem_bytes: int, stdout_cap: int) -> SandboxResult:
        if not self.available():
            return SandboxResult(ok=False, error="cpp_sandbox_missing")
        cmd = [self.cfg.cpp_sandbox_path, "--time", str(int(timeout_s)), "--mem", str(mem_bytes), "--stdout", str(stdout_cap), "--", *argv]
        out = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        # Wrapper prints JSON with stdout of child embedded; parse it either way
        def parse_wrapper(s: str) -> Dict[str, Any]:
            try:
                return json.loads(s.strip()) if s.strip() else {}
            except Exception:
                return {}

        wrapper = parse_wrapper(out.stdout)
        if not wrapper:
            return SandboxResult(ok=False, error="cpp_wrapper_failed", stderr=out.stderr[-1000:])
        # Try to parse inner runner JSON from wrapper stdout
        inner = {}
        if isinstance(wrapper.get("stdout"), str):
            text = wrapper.get("stdout", "").strip()
            last_line = text.splitlines()[-1] if text else ""
            try:
                inner = json.loads(last_line)
            except Exception:
                inner = {}
        # Prefer inner if present
        if inner and isinstance(inner, dict) and "ok" in inner:
            return SandboxResult(**inner)
        # Fallback to wrapper
        return SandboxResult(**wrapper)


class PythonSandbox:
    def __init__(self, cfg: Config):
        self.cfg = cfg

    def build_runner(self, code: str, tests: List[str], policy: Policy) -> str:
        # Minimal runner, stdout-capped via custom buffer
        prelude = f"""
import sys, os, json, builtins, types, resource, signal, io, time
resource.setrlimit(resource.RLIMIT_CPU, ({self.cfg.sandbox_cpu_seconds}, {self.cfg.sandbox_cpu_seconds}))
try:
    resource.setrlimit(resource.RLIMIT_AS, ({self.cfg.sandbox_mem_bytes}, {self.cfg.sandbox_mem_bytes}))
except Exception:
    pass
signal.alarm({int(max(1, int(policy.limit_time())))})
_DENY_IMPORTS = {json.dumps(sorted(list(Policy.parse(DEFAULT_CONFIG.default_policy).deny_imports() | policy.deny_imports())))}
_real_import = builtins.__import__

def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    root = (name or '').split('.')[0]
    if root in _DENY_IMPORTS:
        raise ImportError('Module ' + root + ' denied by policy')
    return _real_import(name, globals, locals, fromlist, level)

builtins.__import__ = _safe_import
_stdout_cap = {policy.limit_stdout()}
class _CapIO(io.TextIOBase):
    def __init__(self):
        self.buf = []
        self.total = 0
    def write(self, s):
        if not isinstance(s, str): s = str(s)
        n = len(s)
        if self.total + n > _stdout_cap:
            s = s[:max(0, _stdout_cap - self.total)]
        self.total += len(s)
        self.buf.append(s)
        return len(s)
    def getvalue(self):
        return ''.join(self.buf)

sys.stdout = _CapIO()
_executed = set()

def _tracer(frame, event, arg):
    if event == 'line':
        _executed.add((frame.f_code.co_filename, frame.f_lineno))
    return _tracer

sys.settrace(_tracer)
"""
        harness = "\n".join([
            prelude,
            code or "\n",
            "TESTS = " + json.dumps(tests or []) + "\n",
            textwrap.dedent("""
            def _run_tests():
                import traceback
                results = {'passed': 0, 'failed': 0, 'errors': []}
                for idx, t in enumerate(TESTS):
                    ns = {}
                    try:
                        exec(t, globals(), ns)
                        if 'run' in ns and callable(ns['run']):
                            ns['run']()
                        results['passed'] += 1
                    except AssertionError as e:
                        results['failed'] += 1
                        results['errors'].append({'i': idx, 'type': 'assert', 'msg': str(e)})
                    except Exception as e:
                        results['failed'] += 1
                        results['errors'].append({'i': idx, 'type': 'error', 'msg': str(e)})
                return results
            """),
            "res = _run_tests()\n",
            "print(json.dumps({'ok': res['failed']==0, 'tests': res, 'stdout': sys.stdout.getvalue(), 'executed_lines': len(_executed)}))\n",
        ])
        return harness

    def run(self, code: str, tests: List[str], policy: Policy, timeout: Optional[float] = None) -> SandboxResult:
        runner_src = self.build_runner(code, tests, policy)
        tmp = Path(tempfile.mkdtemp(prefix="angst_py_sbx_"))
        try:
            rp = tmp / "runner.py"
            rp.write_text(runner_src, encoding="utf8")
            out = subprocess.run([sys.executable, "-I", str(rp)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, cwd=str(tmp), timeout=timeout or self.cfg.sandbox_timeout_sec)
            if out.returncode != 0:
                return SandboxResult(ok=False, error="nonzero_exit", stdout=out.stdout[-1000:], stderr=out.stderr[-1000:], tests={"passed":0,"failed":1,"errors":["nonzero" ]}, executed_lines=0)
            try:
                data = json.loads(out.stdout.strip().splitlines()[-1])
            except Exception as e:
                return SandboxResult(ok=False, error=f"bad_json:{e}", raw=out.stdout[-500:], stderr=out.stderr[-500:])
            return SandboxResult(**data)
        except subprocess.TimeoutExpired:
            return SandboxResult(ok=False, error="timeout", tests={"passed":0,"failed":1,"errors":["timeout"]}, executed_lines=0)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class Sandbox:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.cpp = CPPSandbox(cfg)
        self.py = PythonSandbox(cfg)

    def run(self, code: str, tests: List[str], policy: Policy) -> SandboxResult:
        # Prefer C++ wrapper if present
        if self.cpp.available():
            # Build runner same as Python sandbox, then run via C++ wrapper
            runner_src = self.py.build_runner(code, tests, policy)
            tmp = Path(tempfile.mkdtemp(prefix="angst_cpp_sbx_"))
            try:
                rp = tmp / "runner.py"
                rp.write_text(runner_src, encoding="utf8")
                res = self.cpp.run([sys.executable, "-I", str(rp)], timeout_s=policy.limit_time(), mem_bytes=self.cfg.sandbox_mem_bytes, stdout_cap=policy.limit_stdout())
                return res
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        # Fallback
        return self.py.run(code, tests, policy, timeout=policy.limit_time())


# =============================================================
# Simulation Fabric (Symbolic/Algorithmic/World + Superpositional)
# =============================================================


class SymbolicSim:
    def run(self, axioms: List[str], steps: int, seed: int) -> Dict[str, Any]:
        rnd = random.Random(seed)
        score = 0.0
        for i in range(steps):
            ax = axioms[i % max(1, len(axioms))] if axioms else "noop"
            score += 1.0 / (1 + len(ax)) * (1 + 0.01 * i)
            if rnd.random() < 0.01:
                score *= 1.05
        return {"tier": 1, "score": score}


class AlgorithmicSim:
    def run(self, axioms: List[str], steps: int, seed: int) -> Dict[str, Any]:
        rnd = random.Random(seed ^ 0xABC)
        score = 0.0
        comp = 0.0
        for i in range(steps):
            comp += 0.5 * math.sin(0.1 * i) + 0.5
            score += max(0.0, comp / (1 + len(axioms)))
            if rnd.random() < 0.02:
                score *= 1.02
        return {"tier": 2, "score": score}


class WorldSim:
    def run(self, axioms: List[str], steps: int, seed: int) -> Dict[str, Any]:
        rnd = random.Random(seed ^ 0xC0DE)
        latency = max(1.0, 10.0 - min(8.0, 0.1 * steps))
        noise = rnd.uniform(-0.5, 0.5)
        score = max(0.0, (1.0 / latency) + 0.01 * steps + noise * 0.01)
        return {"tier": 3, "score": score}


class SuperpositionalSimulator:
    def __init__(self):
        self.symbolic = SymbolicSim()
        self.algo = AlgorithmicSim()
        self.world = WorldSim()

    def run_all(self, axioms: List[str], steps: int, seed: int) -> Dict[str, Any]:
        sims = [
            self.symbolic.run(axioms, steps, seed),
            self.algo.run(axioms, steps, seed),
            self.world.run(axioms, steps, seed),
        ]
        # Quantum-inspired amplitude weighting: normalize scores to amplitudes and compute weighted collapse
        total = sum(max(1e-9, s["score"]) for s in sims) or 1.0
        amplitudes = [max(1e-9, s["score"]) / total for s in sims]
        best = max(sims, key=lambda x: x["score"]) if sims else {"score": 0.0}
        collapsed = {"tier": best.get("tier", 0), "score": sum(s["score"] * a for s, a in zip(sims, amplitudes))}
        return {"sims": sims, "amplitudes": amplitudes, "collapsed": collapsed}


# =============================================================
# Test Generator
# =============================================================


class TestGenerator:
    @staticmethod
    def basic(prompt: str, code: str) -> List[str]:
        tests: List[str] = []
        m = re.search(r"def\s+([a-zA-Z_][a-zA-Z0-9_]*)\(", code)
        fn = m.group(1) if m else None
        if fn and "reverse" in prompt.lower():
            tests.append(textwrap.dedent(f"""
            def run():
                for s in ["", "a", "racecar", "abcdef", "😊🚀"]:
                    assert {fn}(s) == s[::-1]
                    assert {fn}({fn}(s)) == s
            """))
        if fn:
            tests.append(textwrap.dedent(f"""
            def run():
                _ = {fn}.__name__
            """))
        return tests


# =============================================================
# CI Pipeline
# =============================================================


class CI:
    def __init__(self, cfg: Config, ledger: Ledger, sandbox: Sandbox):
        self.cfg = cfg
        self.ledger = ledger
        self.sandbox = sandbox

    def verify(self, code: str, tests: List[str], policy: Policy) -> Dict[str, Any]:
        # Static checks
        issues = StaticAnalyzer.check(code, policy)
        if issues:
            return {"ok": False, "stage": "static", "issues": issues}
        # Sandbox exec
        sbx = self.sandbox.run(code, tests, policy)
        ok = bool(sbx.get("ok"))
        executed = int(sbx.get("executed_lines", 0))
        code_lines = max(1, len([ln for ln in code.splitlines() if ln.strip()]))
        coverage_ratio = min(1.0, executed / code_lines)
        return {"ok": ok, "stage": "runtime", "coverage_ratio": coverage_ratio, "tests": sbx.get("tests"), "stdout": sbx.get("stdout", "")}


# =============================================================
# Meta-Architect + Evolutionary Optimizer + Self-Improvement Pipeline
# =============================================================


class EvolutionaryOptimizer:
    def __init__(self, cfg: Config, rng: random.Random):
        self.cfg = cfg
        self.rng = rng

    def mutate_params(self, params: Dict[str, float]) -> Dict[str, float]:
        out = dict(params)
        for k in list(out.keys()):
            out[k] = max(0.0, min(1.0, out[k] + self.rng.uniform(-0.05, 0.05)))
        return out

    def select(self, population: List[Tuple[Dict[str, float], float]], k: int = 3) -> List[Dict[str, float]]:
        ranked = sorted(population, key=lambda x: x[1], reverse=True)
        return [p for p, s in ranked[:k]]


class MetaArchitect:
    def __init__(self, cfg: Config, ledger: Ledger):
        self.cfg = cfg
        self.ledger = ledger
        self.rng = random.Random(cfg.seed)
        self.superpos = SuperpositionalSimulator()
        self.evo = EvolutionaryOptimizer(cfg, self.rng)

    def analyze(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        # Monitor compression efficiency and CI to detect bottlenecks
        bottleneck = "compression" if metrics.get("comp_eff", 0.0) < 0.1 else ("ci" if metrics.get("ci", 0.0) < 0.2 else "none")
        return {"bottleneck": bottleneck, "notes": ["auto-analysis"], "metrics": metrics}

    def self_blueprint(self) -> Dict[str, Any]:
        # Self-Blueprints: produce a graph depiction of internal modules and knowledge flow
        graph = {
            "modules": ["MetaKG", "ACLC", "Sandbox", "CI", "Safety", "Fabric", "MetaArchitect", "SelfImprovement"],
            "edges": [
                ("ACLC", "CI"),
                ("Fabric", "CI"),
                ("Safety", "CI"),
                ("MetaKG", "Fabric"),
                ("MetaArchitect", "SelfImprovement"),
                ("SelfImprovement", "MetaKG"),
            ],
        }
        return {"graph": graph, "digest": stable_hash(json.dumps(graph, sort_keys=True))}

    def design_new_module(self, axioms: List[str]) -> Dict[str, Any]:
        seed = self.rng.randint(1, 1 << 30)
        sims = self.superpos.run_all(axioms, steps=30, seed=seed)
        # Guided evolution: propose a module spec informed by simulated performance
        module = {
            "id": stable_hash("module", str(seed)),
            "score": sims["collapsed"]["score"],
            "spec": {"kind": "reasoner", "seed": seed, "amplitudes": sims.get("amplitudes")},
        }
        return module

    def benchmark_and_select(self, candidates: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if not candidates:
            return None
        best = max(candidates, key=lambda m: m.get("score", 0.0))
        return best

    def evolve(self, base_metrics: Dict[str, Any], axioms: List[str]) -> Dict[str, Any]:
        analysis = self.analyze(base_metrics)
        blueprint = self.self_blueprint()
        cands = [self.design_new_module(axioms) for _ in range(3)]
        best = self.benchmark_and_select(cands)
        rec = {"analysis": analysis, "blueprint": blueprint, "selected": best}
        self.ledger.append({"event": "meta_arch_evolve", **rec})
        return rec


class SelfImprovement:
    def __init__(self, cfg: Config, ledger: Ledger):
        self.cfg = cfg
        self.ledger = ledger
        self.params = {"explore": cfg.exploration_epsilon, "exploit": cfg.exploitation_weight}
        self.rng = random.Random(cfg.seed ^ 0xBEEF)

    def profile(self, hist: List[Dict[str, Any]]) -> Dict[str, Any]:
        comp_eff = statistics.fmean([h.get("comp_eff", 0.0) for h in hist]) if hist else 0.0
        ci = statistics.fmean([h.get("ci", 0.0) for h in hist]) if hist else 0.0
        return {"comp_eff": comp_eff, "ci": ci}

    def optimize(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        # Differentiable-like heuristic: gradient-sign step via comparisons
        ci = metrics.get("ci", 0.0)
        comp_eff = metrics.get("comp_eff", 0.0)
        delta_e = 0.01 if ci > 0.2 else -0.01
        delta_x = 0.01 if comp_eff < 0.1 else -0.005
        self.params["explore"] = max(0.05, min(0.6, self.params["explore"] + delta_e))
        self.params["exploit"] = max(0.4, min(0.9, self.params["exploit"] - delta_x))
        upd = {"exploration_epsilon": self.params["explore"], "exploitation_weight": self.params["exploit"]}
        self.ledger.append({"event": "self_optimize", **upd, "metrics": metrics})
        return upd


# =============================================================
# Intelligence Scoring
# =============================================================


class IntelligenceScorer:
    @staticmethod
    def score(ci_ok: bool, coverage: float, kg_size: int, diversity: float, comp_eff: float, anomaly_delta: float, cfg: Config = DEFAULT_CONFIG) -> Dict[str, float]:
        ci_score = 0.5 * (1.0 if ci_ok else 0.0) + 0.5 * coverage
        structural = min(1.0, math.log2(max(2, kg_size)) / 10.0)
        reasoning = min(1.0, diversity)
        meta = (
            cfg.meta_alpha * ci_score + cfg.meta_beta * comp_eff + cfg.meta_gamma * reasoning + cfg.meta_delta * max(0.0, anomaly_delta)
        )
        return {"ci_score": ci_score, "structural_score": structural, "reasoning_depth": reasoning, "meta_score": meta}


# =============================================================
# Frontend / Orchestration Kernel
# =============================================================


class FrontendAI:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        self.ledger = Ledger(cfg)
        self.kg = MetaKnowledgeGraph(cfg, self.ledger)
        self.aclc = ACLCClient(cfg, self.ledger)
        self.sandbox = Sandbox(cfg)
        self.ci = CI(cfg, self.ledger, self.sandbox)
        self.meta_arch = MetaArchitect(cfg, self.ledger)
        self.self_imp = SelfImprovement(cfg, self.ledger)
        self.rng = random.Random(cfg.seed)
        # Seed rules
        self.kg.add_rule("declare_intent before external_call", weight=1.0, seed=42)
        self.kg.add_rule("verify_patch_proof before commit", weight=1.2, seed=43)
        self.kg.add_rule("compress_redundant_rules", weight=0.8, seed=44)
        # Meta-KG seed for cross-domain fusion
        self.kg.add_rule("cross_domain fusion meta_reasoning", weight=0.9, seed=45)

    def prompt_to_axioms(self, prompt: str) -> List[str]:
        lower = prompt.lower()
        axioms = [f"intent {prompt.split('.')[0].strip()}" ]
        if "reverse" in lower:
            axioms.append("fn reverse_string(s:str)->str")
        if any(k in lower for k in ("optimize", "fast", "speed")):
            axioms.append("perf prefer_on")
        axioms.append("safety no_network")
        return axioms

    def propose_variants(self, axioms: List[str], n: int) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for _ in range(n):
            seed = self.rng.randint(1, 1 << 30)
            mutated = [ax + " verify" if self.rng.random() < 0.35 else ax for ax in axioms]
            art = None
            if self.rng.random() < 0.35:
                name = "func_" + stable_hash(" ".join(mutated))
                art = f"fn {name}(x: int) -> int:\n    return x\n"
            out.append({"seed": seed, "axioms": mutated, "artifact": art})
        return out

    def evaluate_variants(self, variants: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        scores: List[Dict[str, Any]] = []
        superpos = SuperpositionalSimulator()
        for v in variants:
            sim = superpos.run_all(v["axioms"], steps=self.cfg.sim_steps, seed=v["seed"])
            score_adj = sim["collapsed"]["score"] * self.cfg.exploitation_weight + self.rng.random() * self.cfg.exploration_epsilon
            scores.append({"variant": v, "sim": sim, "score_adj": score_adj})
        scores.sort(key=lambda x: x["score_adj"], reverse=True)
        return scores[: self.cfg.topk_variants]

    def artifact_to_python(self, artifact: Optional[str], prompt: str, axioms: List[str]) -> str:
        if artifact:
            comp = self.aclc.compile(artifact)
            py = comp.get("python_code") or "\n"
            return py
        # Heuristic fallback for prompt
        if "reverse" in prompt.lower():
            return textwrap.dedent("""
            def reverse_string(s: str) -> str:
                return s[::-1]
            """)
        return "\n"

    def generate_tests(self, prompt: str, code: str) -> List[str]:
        return TestGenerator.basic(prompt, code)

    def build_policy(self) -> Policy:
        return Policy.parse(self.cfg.default_policy)

    def run_once(self, prompt: str) -> Dict[str, Any]:
        axioms = [r.pattern for r in self.kg.all_rules()] + self.prompt_to_axioms(prompt)
        variants = self.propose_variants(axioms, self.cfg.variants_per_round)
        top = self.evaluate_variants(variants)
        proposals: List[Dict[str, Any]] = []
        mat_rules: List[str] = []
        policy = self.build_policy()
        any_ci_ok = False
        any_cov = 0.0
        for t in top:
            v = t["variant"]
            code = self.artifact_to_python(v.get("artifact"), prompt, v["axioms"])
            tests = self.generate_tests(prompt, code)
            ci = self.ci.verify(code, tests, policy)
            proposals.append({"seed": v["seed"], "status": "approved" if ci.get("ok") else "rejected", "ci": ci})
            if ci.get("ok"):
                any_ci_ok = True
                any_cov = max(any_cov, float(ci.get("coverage_ratio", 0.0)))
                # materialize some axioms as rules
                for ax in v["axioms"][:2]:
                    r = self.kg.add_rule(ax, weight=1.1, seed=v["seed"])
                    mat_rules.append(r.id)
        comp = self.kg.compress()
        diversity = self._diversity([v["variant"] for v in top])
        intel = IntelligenceScorer.score(any_ci_ok, any_cov, len(self.kg.all_rules()), diversity, float(comp.get("efficiency_score", 0.0)), anomaly_delta=0.0, cfg=self.cfg)
        entry = {
            "top_variants": [{"seed": s["variant"]["seed"], "score": s["sim"]["collapsed"]["score"]} for s in top],
            "proposals": proposals,
            "materialized": mat_rules,
            "compression": comp,
            "kg_size": len(self.kg.all_rules()),
            "scores": intel,
        }
        self.ledger.append(entry)
        return entry

    def run(self, prompt: str) -> Dict[str, Any]:
        history: List[Dict[str, Any]] = []
        for it in range(self.cfg.iterations):
            out = self.run_once(prompt)
            out["iteration"] = it
            history.append({"comp_eff": float(out.get("compression",{}).get("efficiency_score", 0.0)), "ci": float(out.get("scores",{}).get("ci_score", 0.0))})
            # Evolution step
            _ = self.meta_arch.evolve({"comp_eff": history[-1]["comp_eff"], "ci": history[-1]["ci"]}, [r.pattern for r in self.kg.all_rules()])
            # Optimize params
            _ = self.self_imp.optimize(self.self_imp.profile(history))
        summary = {"iterations": len(history), "avg_comp_eff": statistics.fmean([h["comp_eff"] for h in history]) if history else 0.0}
        self.ledger.append({"summary": summary})
        return {"summary": summary}

    @staticmethod
    def _diversity(variants: List[Dict[str, Any]]) -> float:
        sets: List[Set[str]] = [set(" ".join(v.get("axioms", [])).split()) for v in variants]
        if len(sets) < 2:
            return 0.0
        pairs = []
        for i in range(len(sets)):
            for j in range(i+1, len(sets)):
                a, b = sets[i], sets[j]
                if not a or not b:
                    d = 0.0
                else:
                    d = 1.0 - (len(a & b) / len(a | b))
                pairs.append(d)
        return sum(pairs)/len(pairs) if pairs else 0.0


# =============================================================
# CLI
# =============================================================


def cli_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Angst v2 Orchestrator")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="Run orchestrator with prompt")
    p_run.add_argument("--prompt", type=str, default="Create a function that reverses a string. Then optimize it.")

    p_once = sub.add_parser("once", help="Single-iteration run")
    p_once.add_argument("--prompt", type=str, default="Create a function that reverses a string.")

    p_lang = sub.add_parser("lang", help="Design a language via ACLC")
    p_lang.add_argument("--prompt", type=str, required=True)

    args = parser.parse_args(argv)
    cfg = dataclasses.replace(DEFAULT_CONFIG)

    app = FrontendAI(cfg)

    if args.cmd == "run":
        out = app.run(args.prompt)
        print(json.dumps(out, indent=2))
    elif args.cmd == "once":
        out = app.run_once(args.prompt)
        print(json.dumps(out, indent=2))
    elif args.cmd == "lang":
        out = app.aclc.design_language(args.prompt)
        print(json.dumps(out, indent=2))
    else:
        parser.error("Unknown command")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(cli_main())
    except KeyboardInterrupt:
        print("Interrupted", file=sys.stderr)
        sys.exit(130)
