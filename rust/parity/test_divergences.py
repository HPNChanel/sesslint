"""Synthetic registry and runner decision-path regressions for RX-P1.3f."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from divergences import (
    END,
    START,
    RegistryError,
    classify,
    fingerprint,
    hash_fixture,
    load_registry,
)

HERE = Path(__file__).resolve().parent
PIN = "e91d50b2ecea57ef4dd900e3b0b87b14946e847e"
FIXTURE = "fixtures/synthetic.jsonl"
COMMAND = ["check", FIXTURE]
INPUT = b"{}\n"
INPUT_SHA256 = hashlib.sha256(INPUT).hexdigest()
LEFT = (0, b"synthetic-reference\n", b"")
RIGHT = (1, b"synthetic-candidate\n", b"")


def entry() -> dict:
    return {
        **fingerprint(PIN, FIXTURE, INPUT_SHA256, COMMAND, LEFT, RIGHT),
        "id": "DIV-synthetic",
        "description": "Synthetic exit and output difference for a test only.",
        "suspected_python_bug": False,
        "reviewer": "synthetic-test-reviewer",
        "date": "2026-11-09",
    }


def markdown(entries: list) -> str:
    return START + json.dumps({"schema_version": 1, "entries": entries}) + END + "\n"


def load_runner():
    loader = importlib.machinery.SourceFileLoader("parity_runner_test", str(HERE / "run"))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    assert spec is not None
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


class RegistryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "registry.md"

    def load(self, text):
        self.path.write_bytes(text.encode("utf-8"))
        return load_registry(self.path)

    def test_shipped_registry_is_empty(self):
        self.assertEqual(load_registry(HERE / "KNOWN_DIVERGENCES.md"), [])

    def test_fixture_hash_crosses_chunk_boundary(self):
        data = b"synthetic" * 150_000
        self.path.write_bytes(data)
        self.assertEqual(hash_fixture(self.path), hashlib.sha256(data).hexdigest())

    def test_approved_exact_capture(self):
        approved = self.load(markdown([entry()]))
        observed = fingerprint(PIN, FIXTURE, INPUT_SHA256, COMMAND, LEFT, RIGHT)
        self.assertEqual(classify(approved, observed), "DIV-synthetic")

    def test_every_identity_dimension_is_bound(self):
        approved = self.load(markdown([entry()]))
        original = fingerprint(PIN, FIXTURE, INPUT_SHA256, COMMAND, LEFT, RIGHT)
        for key in original:
            with self.subTest(key=key):
                changed = dict(original)
                changed[key] = 9 if isinstance(changed[key], int) else "changed"
                self.assertIsNone(classify(approved, changed))
        self.assertNotEqual(
            fingerprint(PIN, FIXTURE, INPUT_SHA256, COMMAND, LEFT, RIGHT)["command_sha256"],
            fingerprint(PIN, FIXTURE, INPUT_SHA256, COMMAND + ["--json"], LEFT, RIGHT)[
                "command_sha256"
            ],
        )

    def test_pending_or_invalid_entries_refused(self):
        mutations = [
            ("reviewer", None),
            ("reviewer", " "),
            ("date", None),
            ("date", "2026-02-30"),
            ("date", "20261109"),
            ("pin", "*"),
            ("fixture_sha256", "F" * 64),
            ("fixture", "fixtures/../private"),
            ("fixture", "fixtures//x"),
            ("fixture", "fixtures\\x"),
            ("fixture", "fixtures/x\nsecret"),
            ("python_exit", True),
            ("rust_exit", "0"),
            ("description", ""),
            ("suspected_python_bug", 1),
            ("id", "DIV-x\nsecret"),
        ]
        for key, value in mutations:
            with self.subTest(key=key, value=value):
                candidate = entry()
                candidate[key] = value
                with self.assertRaises(RegistryError):
                    self.load(markdown([candidate]))
        for key in entry():
            candidate = entry()
            del candidate[key]
            with self.subTest(missing=key), self.assertRaises(RegistryError):
                self.load(markdown([candidate]))
        candidate = entry()
        candidate["unknown"] = "ignored?"
        with self.assertRaises(RegistryError):
            self.load(markdown([candidate]))

    def test_duplicate_id_or_identity_refused(self):
        for field in ("description", "id", "fixture_sha256"):
            candidates = [entry(), copy.deepcopy(entry())]
            candidates[1][field] = (
                "DIV-other"
                if field == "id"
                else ("a" * 64 if field == "fixture_sha256" else "different description")
            )
            with self.subTest(field=field), self.assertRaises(RegistryError):
                self.load(markdown(candidates))

    def test_bad_documents_fail_closed(self):
        documents = [
            "",
            markdown([]) * 2,
            START + "[]" + END,
            START + '{"schema_version":true,"entries":[]}' + END,
            START + '{"schema_version":1,"entries":[],"extra":0}' + END,
            START + '{"schema_version":1,"schema_version":1,"entries":[]}' + END,
            START + '{"schema_version":1,"entries":{}}' + END,
            START + '{"schema_version":1,"entries":[null]}' + END,
            START + "[" * 2000 + END,
            "x" * 1_000_001,
            START + '{"schema_version":' + "9" * 5000 + ',"entries":[]}' + END,
        ]
        for document in documents:
            with self.subTest(length=len(document)), self.assertRaises(RegistryError):
                self.load(document)
        self.path.write_bytes(b"\xff")
        with self.assertRaises(RegistryError):
            load_registry(self.path)
        with self.assertRaises(RegistryError):
            load_registry(self.path.with_name("missing.md"))


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.runner = load_runner()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "fixtures").mkdir()
        (self.root / FIXTURE).write_bytes(INPUT)
        self.binary = self.root / "synthetic-candidate"
        self.binary.write_bytes(b"not executable; capture is a test double")

    def run_case(self, entries, captures, strict=True, rust=True):
        (self.root / "KNOWN_DIVERGENCES.md").write_bytes(markdown(entries).encode())
        runner = self.runner
        out, err = io.StringIO(), io.StringIO()
        with contextlib.ExitStack() as stack:
            for name, value in (("HERE", self.root), ("WORK", self.root)):
                stack.enter_context(patch.object(runner, name, value))
            for name, value in (
                ("load_pin", PIN),
                ("repo_root", self.root),
                ("scratch_path_ok", True),
                ("ensure_worktree", None),
                ("ensure_venv", None),
                ("git_head", PIN),
                ("resolve_invocation", (FIXTURE, COMMAND)),
                ("sesslint_bin", self.binary),
            ):
                stack.enter_context(patch.object(runner, name, return_value=value))
            # Use the real comparator, loaded from the actual source directory.
            stack.enter_context(patch.object(runner, "_COMPARE", None))
            with patch.object(runner, "HERE", HERE):
                comparator = runner.compare_module()
            stack.enter_context(patch.object(runner, "compare_module", return_value=comparator))
            capture = stack.enter_context(patch.object(runner, "capture", side_effect=captures))
            stack.enter_context(contextlib.redirect_stdout(out))
            stack.enter_context(contextlib.redirect_stderr(err))
            args = ["--strict"] if strict else []
            if rust:
                args += ["--rust-bin", str(self.binary)]
            code = runner.main(args)
        return code, out.getvalue(), err.getvalue(), capture.call_count

    def test_pending_fails_before_either_implementation_runs(self):
        pending = entry()
        pending["reviewer"] = None
        for strict in (False, True):
            with self.subTest(strict=strict):
                code, out, err, calls = self.run_case([pending], [], strict=strict)
                self.assertEqual(code, 2)
                self.assertIn("compare=abstain", out)
                self.assertIn("reason=divergences_unapproved", err)
                self.assertEqual(calls, 0)
                self.assertNotIn("synthetic-reference", out + err)

    def test_approved_divergence_does_not_waive_strict_gate(self):
        code, out, _, calls = self.run_case([entry()], [LEFT, RIGHT])
        self.assertEqual(code, 1)
        self.assertEqual(calls, 2)
        self.assertIn("compare=approved_divergence\n", out)
        self.assertIn("divergence_id=DIV-synthetic\n", out)

    def test_approved_non_strict_remains_diagnostic(self):
        code, out, _, _ = self.run_case([entry()], [LEFT, RIGHT], strict=False)
        self.assertEqual(code, 0)
        self.assertIn("compare=approved_divergence\n", out)

    def test_unknown_or_drifted_difference_fails(self):
        for registry, captures in (([], [LEFT, RIGHT]), ([entry()], [LEFT, (2, b"new", b"")])):
            code, out, _, _ = self.run_case(registry, captures)
            self.assertEqual(code, 1)
            self.assertIn("compare=mismatch\n", out)
            self.assertNotIn("divergence_id=", out)

    def test_equal_stays_match(self):
        code, out, _, _ = self.run_case([entry()], [LEFT, LEFT])
        self.assertEqual(code, 0)
        self.assertIn("compare=match\n", out)

    def test_missing_rust_cannot_be_approved(self):
        code, out, _, calls = self.run_case([entry()], [LEFT], rust=False)
        self.assertEqual(code, 1)
        self.assertIn("compare=abstain\n", out)
        self.assertEqual(calls, 1)

    def test_changed_fixture_refuses_classification(self):
        sequence = iter([LEFT, RIGHT])

        def changing_capture(*args):
            (self.root / FIXTURE).write_bytes(b"changed\n")
            return next(sequence)

        code, out, err, _ = self.run_case([entry()], changing_capture)
        self.assertEqual(code, 2)
        self.assertIn("compare=abstain\n", out)
        self.assertIn("reason=fixture_changed\n", err)

    def test_real_cli_rejects_pending_malformed_and_missing_registry(self):
        # Run the unchanged entrypoint in a disposable directory. Invalid
        # registries must fail before Git, venv setup or implementation capture.
        for name in ("run", "divergences.py"):
            (self.root / name).write_bytes((HERE / name).read_bytes())
        (self.root / "PIN").write_bytes((PIN + "\n").encode("ascii"))
        registry = self.root / "KNOWN_DIVERGENCES.md"
        pending = entry()
        pending["reviewer"] = None
        for content, reason in (
            (None, "divergences_unreadable"),
            ("invalid", "divergences_markers"),
            (markdown([pending]), "divergences_unapproved"),
        ):
            with self.subTest(reason=reason):
                if content is not None:
                    registry.write_bytes(content.encode())
                result = subprocess.run(
                    [sys.executable, str(self.root / "run"), "--strict"],
                    cwd=self.root,
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn(b"compare=abstain\n", result.stdout)
                self.assertEqual(result.stderr, ("reason=" + reason + "\n").encode())
                self.assertNotIn(b"synthetic-reference", result.stdout + result.stderr)
                self.assertFalse((self.root / "run-work").exists())


if __name__ == "__main__":
    unittest.main()
