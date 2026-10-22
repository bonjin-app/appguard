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
    if "-r" in sys.argv:
        code = sys.argv[sys.argv.index("-r") + 1]
        if "PHP_SHLIB_SUFFIX" in code:
            print(str(Path(os.environ["STUB_EXTENSION_DIR"]) / (sys.argv[-1] + ".so")))
            sys.exit(0)
        if os.environ.get("STUB_PHP_SHARED_MODULES"):
            if 'extension_loaded("phar")' in code:
                sys.exit(1)
            if 'extension_loaded("iconv")' in code:
                sys.exit(0 if os.environ.get("STUB_BUILTIN_MBSTRING") else 1)
    if os.environ.get("STUB_PHP_SHARED_MODULES") and os.environ["APPGUARD_COMPOSER_PHAR"] in sys.argv:
        encoding = "iconv" if (Path(os.environ["STUB_EXTENSION_DIR"]) / "iconv.so").is_file() else "mbstring"
        required = ["phar"] if os.environ.get("STUB_BUILTIN_MBSTRING") else ["phar", encoding]
        if any("extension=" + str(Path(os.environ["STUB_EXTENSION_DIR"]) / (name + ".so")) not in sys.argv for name in required):
            sys.stderr.write("Composer needs the installed shared Phar/iconv modules\n")
            sys.exit(1)
        if os.environ.get("STUB_PHP_LOAD_FAILURE"):
            sys.stderr.write("Composer could not load the required extension\n")
            sys.exit(23)
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
        self.modules = self.base / "PHP shared extensions"
        self.modules.mkdir()
        for name in ["phar", "iconv"]:
            (self.modules / (name + ".so")).touch()
        self.env["STUB_EXTENSION_DIR"] = str(self.modules)

    def run_runner(self, *args):
        return subprocess.run(["bash", str(RUNNER), *args], env=self.env,
                              cwd=self.base, capture_output=True, text=True)

    def calls(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_check_only_and_temporary_home_cleanup(self):
        result = self.run_runner("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        self.assertEqual(len(calls), 7)
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
        for args in php_calls:
            if self.env["APPGUARD_COMPOSER_PHAR"] in args:
                self.assertEqual(args[:2], ["-n", self.env["APPGUARD_COMPOSER_PHAR"]])
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

    def test_composer_shared_modules_do_not_change_sdk_php_invocations(self):
        # Ubuntu packages Phar/iconv separately; a static local PHP hid this failure.
        # Catch losing the Composer-only extension options or leaking them to SDK tests.
        self.env["STUB_PHP_SHARED_MODULES"] = "1"
        result = self.run_runner()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.calls()
        composer_calls = [c["args"] for c in calls
                          if c["kind"] == "php" and self.env["APPGUARD_COMPOSER_PHAR"] in c["args"]]
        self.assertEqual(len(composer_calls), 3)
        for args in composer_calls:
            self.assertEqual(args[:5], ["-n", "-d", "extension=" + str(self.modules / "phar.so"),
                                       "-d", "extension=" + str(self.modules / "iconv.so")])
        self.assertIn(["-n", "tests/run-all.php"], [c["args"] for c in calls if c["kind"] == "php"])
        self.assertFalse(Path(calls[0]["home"]).parent.exists())

    def test_builtin_mbstring_needs_only_shared_phar_for_composer(self):
        self.env.update(STUB_PHP_SHARED_MODULES="1", STUB_BUILTIN_MBSTRING="1")
        result = self.run_runner("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        args = self.calls()[-1]["args"]
        self.assertEqual(args, ["-n", "-d", "extension=" + str(self.modules / "phar.so"),
                                self.env["APPGUARD_COMPOSER_PHAR"], "--version"])

    def test_shared_mbstring_can_satisfy_composer_without_iconv(self):
        self.env["STUB_PHP_SHARED_MODULES"] = "1"
        (self.modules / "iconv.so").unlink()
        (self.modules / "mbstring.so").touch()
        result = self.run_runner("--check")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls()[-1]["args"],
                         ["-n", "-d", "extension=" + str(self.modules / "phar.so"),
                          "-d", "extension=" + str(self.modules / "mbstring.so"),
                          self.env["APPGUARD_COMPOSER_PHAR"], "--version"])

    def test_missing_or_relative_shared_module_fails_before_composer_and_suites(self):
        self.env["STUB_PHP_SHARED_MODULES"] = "1"
        relative_modules = self.base / "relative modules"
        relative_modules.mkdir()
        for name in ["phar", "iconv"]:
            (relative_modules / (name + ".so")).touch()
        for extension_dir in [str(self.base / "missing modules"), "relative modules"]:
            with self.subTest(extension_dir=extension_dir):
                self.log.unlink(missing_ok=True)
                self.env["STUB_EXTENSION_DIR"] = extension_dir
                result = self.run_runner()
                self.assertNotEqual(result.returncode, 0)
                calls = self.calls()
                self.assertFalse(any(self.env["APPGUARD_COMPOSER_PHAR"] in c["args"] for c in calls))
                self.assertFalse(any("test" in c["args"] or "restore" in c["args"] for c in calls))
                self.assertFalse(Path(calls[0]["home"]).parent.exists())

    def test_shared_module_load_failure_stops_suites_and_cleans_state(self):
        self.env.update(STUB_PHP_SHARED_MODULES="1", STUB_PHP_LOAD_FAILURE="1")
        result = self.run_runner()
        self.assertEqual(result.returncode, 23, result.stderr)
        calls = self.calls()
        self.assertFalse(any("test" in c["args"] or "restore" in c["args"] for c in calls))
        self.assertFalse(Path(calls[0]["home"]).parent.exists())

    def test_bad_arguments_and_missing_runtime_fail_before_execution(self):
        self.assertEqual(self.run_runner("--unknown").returncode, 2)
        self.assertEqual(self.run_runner("--check", "extra").returncode, 2)
        self.env["APPGUARD_GO_CMD"] = str(self.base / "missing")
        self.assertEqual(self.run_runner().returncode, 127)
        self.assertFalse(self.log.exists())


if __name__ == "__main__":
    unittest.main()
