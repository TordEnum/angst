# Angst (Python, Modular)

This is a modular refactor of the iterative rule improvement system.

- Modularized into `angst` package: `kg`, `rsl`, `checks`, `orchestrator`.
- Config-driven parameters in `angst/config.py`.
- Ledger logging with metrics and anomaly detection in `angst/logging_utils.py`.
- API-ready orchestrator, runnable via `python -m angst.cli`.
- Basic tests in `tests/`.

Run:

```bash
python -m angst.cli
```
