import os, json, time, statistics, hashlib
from typing import Dict, Any, List
from .config import DEFAULT_CONFIG, Config

OS_SEP = os.sep

class Ledger:
    def __init__(self, cfg: Config = DEFAULT_CONFIG):
        self.cfg = cfg
        os.makedirs(cfg.out_dir, exist_ok=True)
        self.path = os.path.join(cfg.out_dir, cfg.ledger_file)
        self.chain_path = os.path.join(cfg.out_dir, "chain.jsonl")
        self._last_hash: str | None = None

    @staticmethod
    def now() -> float:
        return time.time()

    def append(self, entry: Dict[str, Any]) -> Dict[str, Any]:
        entry = dict(entry)
        entry["ts"] = self.now()
        with open(self.path, "a", encoding="utf8") as f:
            f.write(json.dumps(entry, default=str) + "\n")
        if self.cfg.chain_enable:
            self._append_chain(entry)
        return entry

    # --- Cryptographic chain ---
    def _load_last_hash(self) -> str:
        if self._last_hash is not None:
            return self._last_hash
        if not os.path.exists(self.chain_path):
            self._last_hash = "0" * 64
            return self._last_hash
        last = None
        with open(self.chain_path, "r", encoding="utf8") as f:
            for line in f:
                if line.strip():
                    last = json.loads(line)
        if last:
            self._last_hash = last.get("hash", "0" * 64)
        else:
            self._last_hash = "0" * 64
        return self._last_hash

    def _append_chain(self, entry: Dict[str, Any]) -> None:
        prev = self._load_last_hash()
        payload = json.dumps(entry, sort_keys=True)
        h = hashlib.sha256((prev + "|" + payload).encode()).hexdigest()
        rec = {"prev": prev, "hash": h, "entry": entry, "ts": self.now()}
        with open(self.chain_path, "a", encoding="utf8") as f:
            f.write(json.dumps(rec, default=str) + "\n")
        self._last_hash = h

    # --- Merkle root over recent ledger entries ---
    def merkle_root(self, max_leaves: int = 1024) -> str | None:
        if not os.path.exists(self.path):
            return None
        try:
            lines: list[str] = []
            with open(self.path, "r", encoding="utf8") as f:
                for line in f:
                    if line.strip():
                        lines.append(line.strip())
            leaves = [hashlib.sha256(l.encode()).hexdigest() for l in lines[-max_leaves:]]
            if not leaves:
                return None
            # Build tree
            level = leaves
            while len(level) > 1:
                nxt: list[str] = []
                for i in range(0, len(level), 2):
                    a = level[i]
                    b = level[i + 1] if i + 1 < len(level) else a
                    nxt.append(hashlib.sha256((a + b).encode()).hexdigest())
                level = nxt
            return level[0]
        except Exception:
            return None

    def aggregate_metrics(self) -> Dict[str, Any]:
        # Compute aggregates over the ledger file
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
        # attach last chain hash if enabled
        if self.cfg.chain_enable and os.path.exists(self.chain_path):
            try:
                last = None
                with open(self.chain_path, "r", encoding="utf8") as f:
                    for line in f:
                        if line.strip():
                            last = json.loads(line)
                if last:
                    out["chain_hash"] = last.get("hash")
            except Exception:
                pass
        return out

    def detect_anomalies(self) -> List[Dict[str, Any]]:
        # Scan ledger for score spikes/drops using z-scores
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
