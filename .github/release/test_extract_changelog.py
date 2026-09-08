"""Release notes must identify both the component and version."""
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name('extract-changelog.sh').resolve()


class ChangelogTests(unittest.TestCase):
    def extract(self, selector, changelog):
        with tempfile.TemporaryDirectory() as directory:
            Path(directory, 'CHANGELOG.md').write_text(changelog)
            return subprocess.run(['bash', str(SCRIPT), selector], cwd=directory,
                                  text=True, capture_output=True, check=False)

    def test_component_collision_and_h2_boundary(self):
        result = self.extract('assay-engine 0.6.0', '''## [0.6.0] - old
Wrong generic notes
## assay-engine 0.6.01 — future
Wrong prefix notes
## assay-engine 0.6.0 — today

Engine notes

### Fixed
Details

## assay-vault 0.6.0 — today
Wrong component notes
''')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'Engine notes\n\n### Fixed\nDetails\n')

    def test_bracketed_component(self):
        result = self.extract('assay-vault 0.5.0', '## [assay-vault 0.5.0]\nVault\n## Next\nWrong\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'Vault\n')

    def test_legacy_version(self):
        result = self.extract('0.6.0', '## [0.6.0] - old\nLegacy\n## Next\nWrong\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, 'Legacy\n')

    def test_no_generic_fallback_for_component(self):
        result = self.extract('assay-engine 0.6.0', '## [0.6.0]\nUnrelated\n')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
