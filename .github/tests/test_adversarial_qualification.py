"""Qualification must run real parser/verifier behavior and reject known negatives."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'scripts/qualification/adversarial_profile.py'

class AdversarialQualificationTests(unittest.TestCase):
    def test_seeded_negatives_never_consume_replay_state(self):
        run = subprocess.run([sys.executable, str(SCRIPT), '--iterations', '160', '--seed', '12932'],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(run.returncode, 0, run.stderr)
        report = json.loads(run.stdout)
        self.assertEqual(report['status'], 'passed')
        self.assertIs(report['baseline_verified'], True)
        self.assertEqual(report['core_mutations'], 160)
        self.assertEqual(report['wire_mutations'], 160)
        self.assertEqual(report['unexpected_acceptances'], 0)
        self.assertEqual(report['negative_replay_claims'], 0)
        self.assertEqual(sum(report['core_reasons'].values()), 160)
        self.assertEqual(sum(report['wire_reasons'].values()), 160)

if __name__ == '__main__':
    unittest.main()
