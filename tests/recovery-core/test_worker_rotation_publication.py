"""Expose the frozen offline rotation suites to the existing model CI job.

Only synthetic tests are loaded. The runtime entrypoints and package builders
are never invoked. Keep the original sibling layout to preserve pinned bytes.
"""
import importlib
from pathlib import Path
import sys
import unittest


BASE = Path(__file__).resolve().parents[2] / "scripts/preparation/worker-rotation-20261015"
PATHS = [str(BASE / name) for name in (
    "rotation-adapter-r2", "rotation-orchestration", "public-deployment-preparation")]
MODULES = ("test_rotation", "test_supply_transport", "test_review_regressions",
           "test_orchestration", "test_public_deploy")


class ScopedSuite(unittest.TestSuite):
    def run(self, result, debug=False):
        original = sys.path[:]
        try:
            sys.path[:0] = PATHS
            return super().run(result, debug)
        finally:
            sys.path[:] = original


def load_tests(loader, tests, pattern):
    original = sys.path[:]
    try:
        sys.path[:0] = PATHS
        return ScopedSuite(loader.loadTestsFromModule(importlib.import_module(name))
                           for name in MODULES)
    finally:
        sys.path[:] = original
