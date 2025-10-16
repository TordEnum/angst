import os, json, time, statistics
from typing import Dict, Any, List
from .config import DEFAULT_CONFIG, Config

OS_SEP = os.sep

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
