"""Exercise orchestration without downloading runtimes or modifying SDK output."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RUNNER = ROOT / "scripts/test-extended-server-sdks.sh"
STUB = r'''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
kind = Path(sys.argv[0]).name.split()[0]
entry = {"kind": kind, "args": sys.argv[1:], "cwd": os.getcwd(),
         "home": os.environ.get("DOTNET_CLI_HOME"),
         "composer_home": os.environ.get("COMPOSER_HOME")}
with open(os.environ["STUB_LOG"], "a") as out:
    out.write(json.dumps(entry) + "\n")
if kind == "dotnet":
    assert os.environ["DOTNET_GENERATE_ASPNET_CERTIFICATE"] == "false"
    assert os.environ["DOTNET_CLI_TELEMETRY_OPTOUT"] == "1"
    assert os.environ["DOTNET_SKIP_FIRST_TIME_EXPERIENCE"] == "1"
    assert os.environ["DOTNET_CLI_HOME"] != str(Path.home())
if kind == "php":
    assert sys.argv[1] == "-n"
    assert os.environ["COMPOSER_DISABLE_NETWORK"] == "1"
if kind == "go":
    assert os.environ["GOTOOLCHAIN"] == "local"
    assert os.environ["GOFLAGS"] == "-mod=readonly"
if os.environ.get("STUB_FAIL") == kind + ":" + " ".join(sys.argv[1:]):
    sys.exit(23)
'''


class RunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="appguard runner ")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.log = self.base / "calls.jsonl"
        self.env = dict(os.environ, STUB_LOG=str(self.log))
        for key in list(self.env):
            if key.startswith("APPGUARD_"):
                del self.env[key]
        for kind, var in [("go", "APPGUARD_GO_CMD"), ("dotnet", "APPGUARD_DOTNET"),
                          ("php", "APPGUARD_PHP_CMD")]:
            executable = self.base / (kind + " executable")
            executable.write_text(STUB)
            executable.chmod(0o700)
            self.env[var] = str(executable)
        composer = self.base / "composer package.phar"
        composer.touch()
        self.env["APPGUARD_COMPOSER_PHAR"] = str(composer)

    def run_runner(self, *args):
        return subprocess.run(["bash", str(RUNNER), *args], env=self.env,
                              cwd=self.base, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_check_only_and_temporary_home_cleanup(self):
        result = self.run_runner("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 5)
        self.assertFalse(any(c["args"][0] in ["test", "restore", "install"] for c in calls))
        self.assertFalse(Path(calls[0]["home"]).parent.exists())

    def test_full_sequence_quotes_paths_and_keeps_fixed_arguments(self):
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        go_calls = [c["args"] for c in calls if c["kind"] == "go"]
        self.assertEqual(go_calls, [["version"], ["test", "-count=1", "./..."],
                                   ["test", "-race", "-count=1", "./..."],
                                   ["vet", "./..."], ["build", "./..."]])
        dotnet_calls = [c["args"] for c in calls if c["kind"] == "dotnet"]
        self.assertEqual([a[0] for a in dotnet_calls], ["--version", "restore", "test", "build", "pack"])
        self.assertIn("--locked-mode", dotnet_calls[1])
        php_calls = [c["args"] for c in calls if c["kind"] == "php"]
        self.assertIn(["-n", "tests/run-all.php"], php_calls)
        install = next(a for a in php_calls if "install" in a)
        self.assertIn("--no-plugins", install)
        self.assertIn("--no-scripts", install)
        self.assertFalse(Path(calls[0]["home"]).parent.exists())

    def test_failure_stops_later_sdks_and_cleans_temporary_home(self):
        self.env["STUB_FAIL"] = "go:test -race -count=1 ./..."
        result = self.run_runner()
        self.assertEqual(result.returncode, 23, result.stderr)
        calls = self.calls()
        self.assertFalse(any("restore" in c["args"] or "install" in c["args"] for c in calls))
        self.assertFalse(Path(calls[0]["home"]).parent.exists())

    def test_bad_arguments_and_missing_runtime_fail_before_execution(self):
        self.assertEqual(self.run_runner("--unknown").returncode, 2)
        self.assertEqual(self.run_runner("--check", "extra").returncode, 2)
        self.env["APPGUARD_GO_CMD"] = str(self.base / "missing")
        self.assertEqual(self.run_runner().returncode, 127)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
