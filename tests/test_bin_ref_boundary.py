#!/usr/bin/env python3
"""Workspace-root boundary tests for the bin/ report builders.

Refs embedded in external artifacts (calibration_report_ref,
pair_manifest_ref, packet refs, ...) are untrusted input: without a
boundary they resolve `../` traversal and absolute paths anywhere on the
host (a poisoned artifact could make a report embed digests of files
outside the workspace). Since the workspace-root guard these tests pin
the fail-closed contract: an escaping ref resolves to None — the same
signal the scripts already use for "not local" — never to an arbitrary
host path.
"""

from __future__ import annotations

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

SCRIPTS = {
    "build-route-execution-report": ROOT / "bin" / "build-route-execution-report.py",
    "build-route-policy-report": ROOT / "bin" / "build-route-policy-report.py",
    "build-route-pairing-report": ROOT / "bin" / "build-route-pairing-report.py",
    "validate-evidence-chain": ROOT / "bin" / "validate-evidence-chain.py",
}


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class RefBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        workspace = Path(self._tmp.name) / "workspace"
        (workspace / "runs" / "r1").mkdir(parents=True)
        (workspace / "runs" / "r2").mkdir(parents=True)
        outside = Path(self._tmp.name) / "outside"
        outside.mkdir()
        (outside / "spoofed.json").write_text("{}", encoding="utf-8")
        self.workspace = workspace
        self.outside = outside
        # Root report sits at the workspace top level; the artifacts it
        # references live in subdirectories (runs/r1, runs/r2, ...).
        self.base_file = workspace / "policy.json"
        self.base_file.write_text("{}", encoding="utf-8")

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def test_escaping_refs_are_refused_for_every_builder(self) -> None:
        for name, path in SCRIPTS.items():
            with self.subTest(script=name):
                module = load(name.replace("-", "_"), path)
                module.set_workspace_root([self.base_file])
                escape = "../../../outside/spoofed.json"
                absolute = str(self.outside / "spoofed.json")
                self.assertIsNone(
                    module.resolve_ref(self.base_file, escape),
                    f"{name}: traversal ref escaped the workspace root",
                )
                self.assertIsNone(
                    module.resolve_ref(self.base_file, absolute),
                    f"{name}: absolute outside ref escaped the workspace root",
                )

    def test_in_workspace_refs_still_resolve(self) -> None:
        for name, path in SCRIPTS.items():
            with self.subTest(script=name):
                module = load(name.replace("-", "_"), path)
                module.set_workspace_root([self.base_file])
                inside_rel = module.resolve_ref(self.base_file, "runs/r2/trace.json")
                inside_dotted = module.resolve_ref(self.base_file, "runs/r1/../../runs/r2/trace.json")
                inside_abs = module.resolve_ref(
                    self.base_file, str(self.workspace / "runs" / "r2" / "trace.json")
                )
                expected = self.workspace / "runs" / "r2" / "trace.json"
                self.assertEqual(inside_rel, expected)
                self.assertEqual(inside_dotted, expected)
                self.assertEqual(inside_abs, expected)

    def test_root_covers_all_operator_supplied_inputs(self) -> None:
        # Two inputs in sibling subtrees: refs may cross the subtrees
        # (their common ancestor is the root) but not leave it.
        module = load("policy_boundary_multi", SCRIPTS["build-route-policy-report"])
        left = self.workspace / "left" / "calibration.json"
        right = self.workspace / "right" / "outcome.json"
        left.parent.mkdir(parents=True, exist_ok=True)
        right.parent.mkdir(parents=True, exist_ok=True)
        left.write_text("{}", encoding="utf-8")
        right.write_text("{}", encoding="utf-8")
        module.set_workspace_root([left, right])
        cross = module.resolve_ref(left, "../right/outcome.json")
        self.assertEqual(cross, right)
        escape = module.resolve_ref(left, "../../../outside/spoofed.json")
        self.assertIsNone(escape)

    def test_unset_root_keeps_library_behavior(self) -> None:
        # Sibling builders import these modules and pass already-resolved
        # paths; with no root configured resolution stays unbounded.
        module = load("pairing_boundary_unset", SCRIPTS["build-route-pairing-report"])
        escape = module.resolve_ref(
            self.base_file, "../outside/spoofed.json"
        )
        self.assertEqual(escape, self.outside / "spoofed.json")


if __name__ == "__main__":
    unittest.main()
