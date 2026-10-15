"""Join-modal invite prefill and signup POST body.

Runs tests/signup_prefill_harness.js, which loads frontend/app.js against a
stub DOM and a stub fetch. No network, no extra packages.
"""
import os
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HARNESS = os.path.join(ROOT, "tests", "signup_prefill_harness.js")


class SignupPrefillTest(unittest.TestCase):
    def test_harness(self):
        result = subprocess.run(
            ["node", "--test", HARNESS],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            self.fail(result.stdout + "\n" + result.stderr)


if __name__ == "__main__":
    unittest.main()
