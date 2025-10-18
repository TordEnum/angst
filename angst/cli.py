import json
from .config import DEFAULT_CONFIG, Config
from .orchestrator import Orchestrator


def main():
    import argparse
    parser = argparse.ArgumentParser(description="Angst modular orchestrator")
    parser.add_argument("--iterations", type=int, default=DEFAULT_CONFIG.iterations)
    parser.add_argument("--quantum", action="store_true", help="Enable quantum-inspired selection")
    parser.add_argument("--no-quantum", action="store_true", help="Disable quantum-inspired selection")
    parser.add_argument("--monitor-patience", type=int, default=DEFAULT_CONFIG.monitor_patience)
    args = parser.parse_args()

    cfg = Config(
        iterations=args.iterations,
        topk_variants=DEFAULT_CONFIG.topk_variants,
        variants_per_round=DEFAULT_CONFIG.variants_per_round,
        sim_steps=DEFAULT_CONFIG.sim_steps,
        compress_threshold=DEFAULT_CONFIG.compress_threshold,
        hierarchical_levels=DEFAULT_CONFIG.hierarchical_levels,
        dedup_normalize=DEFAULT_CONFIG.dedup_normalize,
        exploration_epsilon=DEFAULT_CONFIG.exploration_epsilon,
        exploitation_weight=DEFAULT_CONFIG.exploitation_weight,
        parallel_workers=DEFAULT_CONFIG.parallel_workers,
        rollback_on_regression=DEFAULT_CONFIG.rollback_on_regression,
        anomaly_z_threshold=DEFAULT_CONFIG.anomaly_z_threshold,
        out_dir=DEFAULT_CONFIG.out_dir,
        ledger_file=DEFAULT_CONFIG.ledger_file,
        seed=DEFAULT_CONFIG.seed,
        causal_max_degree=DEFAULT_CONFIG.causal_max_degree,
        causal_learning_rate=DEFAULT_CONFIG.causal_learning_rate,
        causal_steps=DEFAULT_CONFIG.causal_steps,
        quantum_samples=DEFAULT_CONFIG.quantum_samples,
        quantum_temperature=DEFAULT_CONFIG.quantum_temperature,
        enable_quantum=(False if args.no_quantum else (True if args.quantum else DEFAULT_CONFIG.enable_quantum)),
        hdl_sim_steps=DEFAULT_CONFIG.hdl_sim_steps,
        federation_nodes=DEFAULT_CONFIG.federation_nodes,
        monitor_patience=args.monitor_patience,
        chain_enable=DEFAULT_CONFIG.chain_enable,
    )

    print("Starting angst (python, modular) ...")
    orch = Orchestrator(cfg)
    orch.run()
    print("Done. Ledger at:", f"{cfg.out_dir}/{cfg.ledger_file}")


if __name__ == "__main__":
    main()
