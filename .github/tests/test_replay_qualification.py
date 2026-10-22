"""Run the owned-process qualification CLI rather than inspecting its source."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/qualification/replay_resilience.py'


class QualificationTests(unittest.TestCase):
    def test_missing_runtime_fails_without_success_report(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--redis-server', '/missing/appguard-test-redis'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stderr), {'status': 'failed', 'code': 'QUALIFICATION_FAILED'})
        self.assertEqual(result.stdout, '')

    @unittest.skipUnless(os.environ.get('APPGUARD_REDIS_SERVER'), 'explicit disposable-process Redis binary required')
    def test_owned_crash_recovery_capacity_timeout_and_load(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--redis-server', os.environ['APPGUARD_REDIS_SERVER'],
                                 '--iterations', '40', '--concurrency', '4'], capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report['status'], 'passed')
        for name in ['process_crash_replay_preserved', 'outage_fail_closed', 'noeviction_capacity_fail_closed',
                     'atomic_single_winner', 'socket_timeout_fail_closed', 'temporary_state_removed']:
            self.assertIs(report['scenarios'][name], True, name)
        self.assertEqual(report['load']['unique_claims'], 40)
        self.assertEqual(report['load']['replays_rejected'], 40)
        self.assertEqual(report['load']['failures'], 0)
        self.assertGreater(report['load']['p95_ms'], 0)
        self.assertEqual(report['load']['concurrency'], 4)
        self.assertEqual(report['durability_scope'], 'owned process crash with appendonly=yes, appendfsync=always, noeviction; not host/disk/replica failure')

    def test_fault_injection_rejects_external_url_argument(self):
        result = subprocess.run([sys.executable, str(SCRIPT), '--url', 'redis://127.0.0.1:6379/0'],
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, '')


if __name__ == '__main__':
    unittest.main()
