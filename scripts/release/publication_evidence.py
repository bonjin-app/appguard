"""Recheck a complete, internally consistent scan set before public staging."""
import hashlib
import json
from pathlib import Path

REQUIRED_CHECKS = frozenset((
    'maven-runtime', 'syft', 'trivy-sbom', 'trivy-licenses', 'trivy-secrets',
    'syft-maven-runtime', 'trivy-maven-runtime', 'trivy-maven-runtime-licenses',
))
REPORT_CHECKS = ('trivy-sbom', 'trivy-licenses', 'trivy-secrets',
                 'trivy-maven-runtime', 'trivy-maven-runtime-licenses')
KINDS = ('Vulnerabilities', 'Secrets', 'Licenses')


class EvidenceDenied(ValueError):
    """Only fixed reason codes may cross the public status boundary."""
    def __init__(self, reason):
        self.reason = reason
        super().__init__(reason)


def read_evidence(path):
    path = Path(path)
    if not path.is_file() or path.is_symlink() or path != path.resolve():
        raise EvidenceDenied('scan_evidence_unverified')
    try:
        value = json.loads(path.read_text())
    except (OSError, ValueError, UnicodeError):
        raise EvidenceDenied('scan_evidence_unverified') from None
    if not isinstance(value, dict):
        raise EvidenceDenied('scan_evidence_unverified')
    return value


def count_findings(report):
    if (not isinstance(report, dict) or type(report.get('SchemaVersion')) is not int
            or report['SchemaVersion'] != 2 or not isinstance(report.get('Results'), list)):
        raise EvidenceDenied('scan_evidence_unverified')
    counts = dict.fromkeys(KINDS, 0)
    for result in report['Results']:
        if not isinstance(result, dict):
            raise EvidenceDenied('scan_evidence_unverified')
        for kind in KINDS:
            findings = result.get(kind, [])
            if not isinstance(findings, list) or any(not isinstance(x, dict) for x in findings):
                raise EvidenceDenied('scan_evidence_unverified')
            counts[kind] += len(findings)
    return counts


def validate_report_binding(scans, status, command, report):
    name = command['name']
    target = ('source' if name == 'trivy-secrets' else
              'sbom-maven-runtime.cdx.json' if 'maven-runtime' in name else 'sbom.cdx.json')
    artifact = command.get('scan_artifact_name')
    if (not isinstance(artifact, str) or not artifact.startswith('/') or Path(artifact).name != target
            or report.get('ArtifactName') != artifact
            or report.get('ArtifactType') != ('filesystem' if name == 'trivy-secrets' else 'cyclonedx')):
        raise EvidenceDenied('scan_evidence_unverified')
    if command.get('report_sha256') != hashlib.sha256((scans / (name + '.json')).read_bytes()).hexdigest():
        raise EvidenceDenied('scan_evidence_unverified')
    if name == 'trivy-secrets':
        expected = status.get('candidate_manifest_sha256')
    else:
        read_evidence(scans / target)  # require a regular, non-symlink input
        expected = hashlib.sha256((scans / target).read_bytes()).hexdigest()
    if (not isinstance(expected, str) or len(expected) != 64
            or command.get('input_sha256') != expected):
        raise EvidenceDenied('scan_evidence_unverified')


def validate_scan_evidence(scans, status):
    """Aggregate flags and process exit codes alone cannot authorize copying."""
    if not isinstance(status, dict) or 'error' in status:
        raise EvidenceDenied('scan_evidence_unverified')
    rows = status.get('commands')
    if not isinstance(rows, list) or len(rows) != len(REQUIRED_CHECKS):
        raise EvidenceDenied('scan_evidence_unverified')
    commands = {}
    for row in rows:
        if (not isinstance(row, dict) or not isinstance(row.get('name'), str)
                or row['name'] not in REQUIRED_CHECKS or row['name'] in commands
                or type(row.get('returncode')) is not int):
            raise EvidenceDenied('scan_evidence_unverified')
        commands[row['name']] = row
    if set(commands) != REQUIRED_CHECKS:
        raise EvidenceDenied('scan_evidence_unverified')
    totals = dict.fromkeys(KINDS, 0)
    for name in REPORT_CHECKS:
        command = commands[name]
        report = read_evidence(scans / (name + '.json'))
        validate_report_binding(scans, status, command, report)
        if command.get('report_available') is not True:
            raise EvidenceDenied('scan_evidence_unverified')
        actual = count_findings(report)
        recorded = command.get('finding_counts')
        if (not isinstance(recorded, dict) or set(recorded) != set(KINDS)
                or any(type(recorded[k]) is not int or recorded[k] != actual[k] for k in KINDS)):
            raise EvidenceDenied('scan_evidence_unverified')
        for kind in KINDS:
            totals[kind] += actual[kind]
    if totals['Secrets']:
        raise EvidenceDenied('secret_findings')
    if totals['Vulnerabilities']:
        raise EvidenceDenied('vulnerability_findings')
    if any(row['returncode'] != 0 for row in commands.values()):
        raise EvidenceDenied('scan_checks_failed')
    if status.get('automated_checks_passed') is not True:
        raise EvidenceDenied('scan_evidence_unverified')
    return commands
