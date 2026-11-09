"""Infrastructure regressions: a broken batch must not become a parity PASS."""

import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from cases import encoded, generate
from run import batch, compare, corpus_for, responses


class RunnerTests(unittest.TestCase):
    def test_seeded_corpus(self):
        self.assertEqual(generate(17, 40), generate(17, 40))
        self.assertNotEqual(generate(17, 40), generate(18, 40))

    def test_case_budget(self):
        for count in (0, -1, 100_001, True):
            with self.assertRaises(ValueError):
                generate(17, count)

    def test_corpus_budget(self):
        with patch("run.MAX_CORPUS", 20), self.assertRaisesRegex(ValueError, "corpus_budget"):
            corpus_for(17, 40)

    def test_missing_extra_duplicate_and_reordered_output(self):
        rows = [{"id": i, "ok": True, "output": "x"} for i in range(2)]
        for sequence in (rows[:1], rows + rows, rows[::-1], [rows[0], rows[0]]):
            with self.assertRaises(ValueError):
                responses(b"".join(map(encoded, sequence)), 2)

    def test_invalid_framing_status_and_id(self):
        for raw in (
            b"",
            b"{}",
            b"{}\n",
            b"[]\n",
            b'{"id":false,"ok":true}\n',
            b'{"id":0,"ok":1}\n',
        ):
            with self.assertRaises(ValueError):
                responses(raw, 1)

    def test_mismatch_and_json_type_distinction(self):
        case = [{"id": 0, "op": "codec", "input": "synthetic"}]
        left = encoded({"id": 0, "ok": True, "output": True})
        right = encoded({"id": 0, "ok": True, "output": 1})
        self.assertEqual(compare(case, left, left), [])
        mismatch = compare(case, left, right)
        self.assertEqual(len(mismatch), 1)
        self.assertEqual(mismatch[0]["id"], 0)
        self.assertNotIn("synthetic", str(mismatch))

    def test_nonzero_timeout_and_output_budget_fail(self):
        with tempfile.TemporaryDirectory() as name:
            directory = Path(name)
            with self.assertRaises(ValueError):
                batch(
                    [sys.executable, "-c", "raise SystemExit(3)"],
                    b"",
                    directory,
                    "exit",
                    time.monotonic() + 5,
                )
            with self.assertRaises(subprocess.TimeoutExpired):
                batch(
                    [sys.executable, "-c", "import time; time.sleep(5)"],
                    b"",
                    directory,
                    "slow",
                    time.monotonic() + 0.1,
                )
            with patch("run.MAX_OUTPUT", 10), self.assertRaises(ValueError):
                batch(
                    [sys.executable, "-c", "print('x'*20)"],
                    b"",
                    directory,
                    "large",
                    time.monotonic() + 5,
                )
            with self.assertRaises(ValueError):
                batch([sys.executable], b"", directory, "expired", time.monotonic() - 1)


if __name__ == "__main__":
    unittest.main()
