from angst.orchestrator import Orchestrator
from angst.config import DEFAULT_CONFIG

def test_orchestrator_runs():
    o = Orchestrator(DEFAULT_CONFIG)
    o.run()
    # should have appended a summary at the end; no exception is success
