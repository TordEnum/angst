import json
from .config import DEFAULT_CONFIG
from .orchestrator import Orchestrator


def main():
    print("Starting angst (python, modular) ...")
    orch = Orchestrator(DEFAULT_CONFIG)
    orch.run()
    print("Done. Ledger at:", f"{DEFAULT_CONFIG.out_dir}/{DEFAULT_CONFIG.ledger_file}")


if __name__ == "__main__":
    main()
