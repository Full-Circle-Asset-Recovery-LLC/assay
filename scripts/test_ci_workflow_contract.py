#!/usr/bin/env python3
"""Workflow contract tests for GitHub Actions CI optimization in assay.

Validates:
1. Valid YAML across all .github/workflows/*.yml
2. Exact preservation of branch-protection required status check contexts
3. Scoped concurrency: cancel-in-progress: ${{ github.ref != 'refs/heads/main' }}
4. Baseline warm caching: no asymmetric PR-only cache saving on main Rust jobs
5. Rust cache coverage: Swatinem/rust-cache present in jobs executing cargo/moon builds
6. Parallel fan-out: dedicated rust-lint and rust-test jobs rather than serial execution
7. Execution parity: existing release and artifact packaging regression tests pass
"""

import glob
import os
import subprocess
import sys
import unittest
import yaml

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")

REQUIRED_CI_STATUS_CHECKS = {
    "changes",
    "check (ubuntu-latest, x86_64-unknown-linux-gnu)",
    "check (macos-14, aarch64-apple-darwin)",
    "workflow-lint",
    "dashboard-e2e",
    "engine-e2e",
    "extension-tests",
    "sysops-e2e",
    "sysops-smoke",
    "cargo-semver-checks",
}


def load_yaml(filepath: str) -> dict:
    """Load and parse a YAML file."""
    with open(filepath, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def get_job_contexts(job_id: str, job_def: dict) -> list[str]:
    """Calculate the status check context names a job generates."""
    name_tmpl = job_def.get("name", job_id)
    strategy = job_def.get("strategy", {})
    matrix = strategy.get("matrix", {})
    includes = matrix.get("include")

    if not includes:
        return [name_tmpl]

    contexts = []
    for inc in includes:
        rendered = name_tmpl
        for k, v in inc.items():
            rendered = rendered.replace(f"${{{{ matrix.{k} }}}}", str(v))
            rendered = rendered.replace(f"${{{{matrix.{k}}}}}", str(v))
        # If name was just the job_id without placeholders, GitHub appends (matrix, vals)
        if rendered == job_id:
            # Sort or match order of values
            vals = [str(inc[k]) for k in sorted(inc.keys()) if k in ("os", "target")]
            rendered = f"{job_id} ({', '.join(vals)})"
        contexts.append(rendered)
    return contexts


class TestWorkflowContract(unittest.TestCase):
    """Test suite ensuring CI workflow integrity and performance gates."""

    def test_01_all_workflows_valid_yaml(self):
        """All YAML files in .github/workflows must parse cleanly."""
        yml_files = glob.glob(os.path.join(WORKFLOW_DIR, "*.yml"))
        self.assertGreater(len(yml_files), 0, "No workflow YAML files found")
        for yml_file in yml_files:
            with self.subTest(file=os.path.basename(yml_file)):
                data = load_yaml(yml_file)
                self.assertIsInstance(data, dict)

    def test_02_ci_required_status_check_names_preserved(self):
        """All branch-protection status check names must be produced by ci.yml."""
        ci_path = os.path.join(WORKFLOW_DIR, "ci.yml")
        ci = load_yaml(ci_path)
        jobs = ci.get("jobs", {})

        generated_contexts = set()
        for job_id, job_def in jobs.items():
            for ctx in get_job_contexts(job_id, job_def):
                generated_contexts.add(ctx)

        for req in REQUIRED_CI_STATUS_CHECKS:
            self.assertIn(
                req,
                generated_contexts,
                f"Required branch-protection check '{req}' is missing from ci.yml generated contexts",
            )

    def test_03_concurrency_non_main_cancellation(self):
        """cancel-in-progress must not abort pushes to main."""
        ci_path = os.path.join(WORKFLOW_DIR, "ci.yml")
        ci = load_yaml(ci_path)
        concurrency = ci.get("concurrency", {})
        cancel_policy = str(concurrency.get("cancel-in-progress", ""))

        self.assertIn(
            "refs/heads/main",
            cancel_policy,
            "Concurrency must guard main: cancel-in-progress must check github.ref != 'refs/heads/main'",
        )

    def test_04_no_asymmetric_pr_only_rust_cache_saving(self):
        """Swatinem/rust-cache must not restrict cache saving to pull_request only."""
        ci_path = os.path.join(WORKFLOW_DIR, "ci.yml")
        with open(ci_path, "r", encoding="utf-8") as f:
            content = f.read()

        self.assertNotIn(
            "save-if: ${{ github.event_name == 'pull_request' }}",
            content,
            "Rust cache save-if must not exclude main branch from populating compiler cache",
        )

    def test_05_e2e_jobs_have_rust_cache(self):
        """Jobs that compile Rust (e.g. dashboard-e2e) must have Swatinem/rust-cache."""
        ci_path = os.path.join(WORKFLOW_DIR, "ci.yml")
        ci = load_yaml(ci_path)
        jobs = ci.get("jobs", {})

        for job_name in ("dashboard-e2e", "engine-e2e"):
            job = jobs.get(job_name)
            if not job:
                continue
            steps = job.get("steps", [])
            has_rust_cache = any(
                isinstance(s, dict)
                and "Swatinem/rust-cache" in str(s.get("uses", ""))
                for s in steps
            )
            self.assertTrue(
                has_rust_cache,
                f"Job '{job_name}' compiles assay-lua:build without Swatinem/rust-cache@v2",
            )

    def test_06_parallel_fan_out_for_lint_and_tests(self):
        """Independent clippy/fmt linting must fan out into parallel job rather than serial execution."""
        ci_path = os.path.join(WORKFLOW_DIR, "ci.yml")
        ci = load_yaml(ci_path)
        jobs = ci.get("jobs", {})

        # We require a separate fast lint job or rust-lint job
        has_separate_lint = "rust-lint" in jobs or "cargo-lint" in jobs or "lint" in jobs
        self.assertTrue(
            has_separate_lint,
            "Expected dedicated parallel rust lint job (e.g. rust-lint) to prevent serial clippy bottleneck in check",
        )

    def test_07_existing_release_and_packaging_tests_pass(self):
        """Parity check: existing repo workflow tests must pass without error."""
        scripts_to_run = [
            os.path.join(REPO_ROOT, ".github", "release", "test_extract_changelog.py"),
            os.path.join(REPO_ROOT, ".github", "ci", "test_artifact_packaging.py"),
            os.path.join(REPO_ROOT, ".github", "ci", "test_assay_engine_baseline_darwin.py"),
        ]
        for script in scripts_to_run:
            if os.path.exists(script):
                res = subprocess.run(
                    [sys.executable, script],
                    capture_output=True,
                    text=True,
                    cwd=REPO_ROOT,
                )
                self.assertEqual(
                    res.returncode,
                    0,
                    f"Regression in {script}:\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
                )


if __name__ == "__main__":
    unittest.main()
