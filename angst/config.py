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

    # Causal modeler
    causal_max_degree: int = 2
    causal_learning_rate: float = 0.05
    causal_steps: int = 200

    # Quantum-inspired reasoning
    quantum_samples: int = 64
    quantum_temperature: float = 1.0
    enable_quantum: bool = True

    # Hardware co-design
    hdl_sim_steps: int = 32

    # Federation / distributed intelligence
    federation_nodes: int = 3

    # Monitoring / convergence
    monitor_patience: int = 3

    # Cryptographic ledger
    chain_enable: bool = True

DEFAULT_CONFIG = Config()
