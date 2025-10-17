from dataclasses import dataclass
from typing import List

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
