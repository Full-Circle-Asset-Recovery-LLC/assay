"""Exercise the deployed workflow's GLIBC gate before main-only packaging."""
import os
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / 'workflows/ci.yml'


class PackagingTests(unittest.TestCase):
    def check_symbols(self, symbols):
        workflow = WORKFLOW.read_text()
        start = workflow.index('GLIBC_MAX_REQUIRED="$(python3')
        script = workflow[start:].split("<<'PY'\n", 1)[1].split('\n          PY\n', 1)[0]
        script = textwrap.dedent(script)
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory, 'readelf')
            executable.write_text(f'#!{sys.executable}\nprint({symbols!r})\n')
            executable.chmod(0o700)
            environment = dict(os.environ, PATH=directory + os.pathsep + os.environ['PATH'])
            return subprocess.run([sys.executable, '-', 'fixture-binary'], input=script,
                                  text=True, capture_output=True, env=environment, check=False)

    def test_supported_symbols(self):
        result = self.check_symbols('GLIBC_2.2.5 GLIBC_2.34 GLIBC_2.35')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), '2.35')

    def test_newer_symbols_rejected(self):
        result = self.check_symbols('GLIBC_2.36')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('newer than 2.35', result.stderr)

    def test_missing_symbols_rejected(self):
        result = self.check_symbols('No GLIBC symbols')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('no GLIBC symbol requirements', result.stderr)


if __name__ == '__main__':
    unittest.main()
