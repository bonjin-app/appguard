#!/usr/bin/env python3
"""Stage three privacy-bounded CI evidence files; never approve operating claims.

Standalone stdlib validation deliberately imports no candidate/release modules.
Original input bytes are retained only after recursive schema validation.
"""
import argparse
import ctypes
from datetime import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import sys

MAX_BYTES = 2 * 1024 * 1024
ROLES = ('gateway', 'backend', 'redis')
CHECKS = ('resource_and_isolation_inspection', 'effective_process_restrictions', 'signed_fidelity',
    'replay_rejected', 'backend_bypass_zero_dispatch', 'absolute_upload_deadline_zero_dispatch',
    'malformed_zero_dispatch', 'redis_outage_denied', 'redis_recovery',
    'redis_restart_replay_retained', 'owned_container_cleanup', 'provenance_unchanged')
RECEIPT_LIMITATIONS = ('owned local Linux Docker daemon only', 'no external security or license approval',
    'no provider account or physical device evidence', 'image vulnerabilities require a separate current scan')
COVERAGE_LIMITATIONS = ('redis_native_binary_unverified', 'native_runtimes_unverified', 'complete_dependency_closure_unverified')
OP_LIMITATIONS = ('sampled resource points are not leak or long-term capacity proof',
    'cgroup v2 is required for effective resource evidence',
    'Docker CLI memory excludes inactive file cache and is rounded',
    'no external security, provider, production or physical-device approval')


def require(value):
    if not value:
        raise ValueError('container_evidence_unverified')


def fields(required, optional=None):
    optional = optional or {}
    def check(value):
        require(type(value) is dict and set(required) <= set(value) <= set(required) | set(optional))
        for key, item in value.items():
            (required[key] if key in required else optional[key])(item)
    return check


def literal(expected):
    def check(value):
        require(type(value) is type(expected) and value == expected)
        if type(expected) is list:
            for actual, wanted in zip(value, expected): literal(wanted)(actual)
        elif type(expected) is dict:
            for key in expected: literal(expected[key])(value[key])
    return check


def integer(low=0, high=2**53-1):
    def check(value):
        require(type(value) is int and low <= value <= high)
    return check


def number(value):
    require(type(value) in (int, float) and math.isfinite(value) and 0 <= value <= 2**53-1)


def pattern(regex, limit=4096):
    def check(value):
        require(type(value) is str and len(value.encode()) <= limit and re.fullmatch(regex, value) is not None)
    return check


def enum(*values):
    def check(value):
        require(type(value) is str and value in values)
    return check


def nullable(check):
    return lambda value: check(value) if value is not None else None


def sequence(check, maximum=2048):
    def validate(value):
        require(type(value) is list and len(value) <= maximum)
        for item in value: check(item)
    return validate


def mapping(key_check, value_check, minimum=0, maximum=2048):
    def validate(value):
        require(type(value) is dict and minimum <= len(value) <= maximum)
        for key, item in value.items(): key_check(key); value_check(item)
    return validate


BOOL = lambda value: require(type(value) is bool)
COUNT = integer()
SHA = pattern(r'[0-9a-f]{64}')
COMMIT = pattern(r'(?:[0-9a-f]{40}|[0-9a-f]{64})')
IMAGE = pattern(r'sha256:[0-9a-f]{64}')
UTC = pattern(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,9})?Z', 40)
VERSION = pattern(r'[0-9]{1,4}(?:\.[0-9]{1,4}){1,3}', 24)
roles = lambda schema: fields({role: schema for role in ROLES})
COUNTERS = fields({key: COUNT for key in ('auth','key','replay','dispatch','resource')})
STATE = fields(dict(running=BOOL,oom_killed=BOOL,exit_code=integer(-128,255),restart_count=COUNT,started_at=UTC))
CONSTRAINT_NAMES = ('image_id_valid','nonroot_user','root_readonly','not_privileged','all_capabilities_dropped',
    'no_added_capabilities','no_new_privileges','private_pid_ipc','no_device_passthrough','memory_bounded',
    'swap_bounded','pids_bounded','cpu_bounded','logging_bounded','tmpfs_bounded','expected_mounts',
    'network_namespace_expected','publication_expected')
CAUSE_NAMES = ('permission_denied','read_only_filesystem','disk_full','port_unavailable','dependency_unhealthy',
    'file_missing','invalid_executable','operation_not_permitted','cgroup_failure','sysctl_failure','mount_failure',
    'namespace_failure','security_profile_failure','logging_configuration_invalid','container_runtime_failure',
    'memory_allocation_failed','native_thread_unavailable','gateway_start_failed','backend_start_failed')
FAILURE = fields(dict(category=enum('cancelled','metadata_invalid','invariant_failed','io_failed','unclassified',
    'nonzero_exit','timeout','output_limit'),exit_code=nullable(integer(-128,255)),
    causes=sequence(enum(*CAUSE_NAMES),len(CAUSE_NAMES))))
STARTUP = fields(dict(schema=literal(1),complete=BOOL,budget_exhausted=BOOL,discovered_containers=COUNT,
    ownership_rejections=COUNT,metadata_errors=COUNT,failure=FAILURE,volume_owned_valid=nullable(BOOL),
    services=roles(fields(dict(present=BOOL,running=nullable(BOOL),exit_code=nullable(integer(-128,255)),
        oom_killed=nullable(BOOL),state_error_present=nullable(BOOL),state_error_causes=sequence(enum(*CAUSE_NAMES),32),
        health=nullable(enum('healthy','unhealthy','starting','none','unknown')),health_failures=nullable(COUNT),
        restart_count=nullable(COUNT),constraints=fields({key:nullable(BOOL) for key in CONSTRAINT_NAMES}),
        limits=fields({key:nullable(COUNT) for key in ('memory_bytes','swap_bytes','pids','nano_cpus')}),
        log_causes=sequence(enum(*CAUSE_NAMES),32))))))
RESOURCE_POINT = roles(fields(dict(state=STATE,restriction_sha256=SHA,
    docker=fields(dict(cpu_percent=number,memory_bytes=COUNT,memory_limit_bytes=COUNT,pids=COUNT)),
    cgroup=fields(dict(version=literal(2),**{key:COUNT for key in ('memory_bytes','memory_limit_bytes',
        'swap_limit_bytes','swap_bytes','memory_oom_events','memory_oom_kills','memory_max_events',
        'cpu_usage_usec','cpu_throttled_usec','cpu_throttled_periods','cpu_periods','cpu_quota_usec',
        'cpu_period_usec','pids','pids_limit')})))))
DIAGNOSTIC = fields(dict(stage=enum('ownership_inspection','runtime_validation','restriction_comparison',
    'stats_readback','stats_normalization','cgroup_readback','cgroup_normalization','stats_cgroup_comparison',
    'state_normalization','completed'),role=nullable(enum(*ROLES)),code=nullable(enum('restriction_changed',
    'stats_schema','stats_json','stats_identity','stats_cpu','stats_memory','stats_pids','stats_roles',
    'cgroup_schema','cgroup_sections','cgroup_scalar','cgroup_metric_key','cgroup_metric_value','cgroup_required_fields','cgroup_cpu_quota',
    'cgroup_limits','cgroup_usage_and_swap','stats_cgroup_limits','container_state')),
    field=nullable(enum('ID','CPUPerc','MemUsage','PIDs','memory.current','memory.max','memory.swap.max',
        'memory.swap.current','memory.events','cpu.stat','cpu.max','pids.current','pids.max',
        'oom','oom_kill','max','usage_usec','throttled_usec','nr_throttled','nr_periods','additional_metric')),
    numbers=mapping(enum('memory_limit_bytes','expected_memory_limit_bytes','pids_limit','expected_pids_limit',
        'cpu_quota_usec','cpu_period_usec','expected_nano_cpus','memory_bytes','pids','swap_limit_bytes',
        'swap_bytes','docker_memory_limit_bytes','docker_pids'),number,maximum=32),
    checks=mapping(enum('memory_limit_matches','pids_limit_matches','cpu_limit_matches','core_scheduling_metric_present',
        'memory_usage_bounded','pids_usage_bounded','swap_disabled','container_id_unchanged','image_unchanged',
        'config_unchanged','host_config_unchanged','ports_unchanged','mounts_unchanged','mount_count_unchanged',
        'mount_order_only_changed','mount_type_unchanged','mount_name_unchanged','mount_source_unchanged',
        'mount_destination_unchanged','mount_driver_unchanged','mount_mode_unchanged','mount_rw_unchanged',
        'mount_propagation_unchanged','mount_other_fields_unchanged'),BOOL,maximum=32)),
    dict(constraints=roles(fields({key:nullable(BOOL) for key in CONSTRAINT_NAMES}))))
ERROR_CODES = ('APPLICATION_UNAVAILABLE','AUTHENTICATION_REQUIRED','BACKEND_TIMEOUT','BACKEND_UNAVAILABLE',
    'DIGEST_MISMATCH','IDENTITY_UNAVAILABLE','INGRESS_OVERLOADED','INVALID_REQUEST','INVALID_SIGNATURE',
    'INVALID_TIME','KEY_REJECTED','KEY_RESOLVER_UNAVAILABLE','REPLAY_DETECTED','REPLAY_STORE_UNAVAILABLE',
    'UNSUPPORTED_PROFILE','UPLOAD_TIMEOUT')
OUTCOME = fields(dict(missing_status=COUNT,invalid_status=COUNT,unrecognized_error_body=COUNT,transport_errors=COUNT,
    statuses=sequence(fields(dict(status=integer(100,599),count=COUNT)),500),
    error_codes=fields({key:COUNT for key in ERROR_CODES})))
SOAK = fields(dict(**{key:COUNT for key in ('signed_requests','replay_requests','fidelity_failures','replay_failures','transport_errors')},
    **{key:number for key in ('requested_seconds','concurrency','elapsed_seconds','requests_per_second','error_rate')},
    latency=fields(dict(samples=COUNT,**{key:number for key in ('min_ms','max_ms','mean_ms','p50_upper_bound_ms','p95_upper_bound_ms','p99_upper_bound_ms')},
        histogram_upper_bounds_ms=literal([1,2,5,10,20,50,100,200,500,1000,2000,5000,10000]),
        histogram_counts=sequence(COUNT,14))),outcomes=fields(dict(schema=literal(1),normal=OUTCOME,replay=OUTCOME))))
OPERATIONAL = fields(dict(schema=literal(1),scope=literal('owned resource-constrained Linux containers; synthetic signed/replay HTTP traffic'),
    requested_seconds=integer(1,3600),concurrency=integer(1,32),phase=enum('pending','resources_before','traffic','resources_after','backend_restart','completed'),
    passed=BOOL,release_ready=literal(False),checks=fields({key:BOOL for key in ('sustained_traffic','counter_fidelity','runtime_unchanged',
        'no_oom_or_restart','backend_restart_replay_retained','owned_container_cleanup','provenance_unchanged')}),limitations=literal(list(OP_LIMITATIONS))),
    dict(backend_restart=fields(dict(counter_reset_expected=BOOL,original_replay_status=literal(403),recovered=BOOL,recovery_seconds=number,
        redis_run_unchanged=BOOL,scope=literal('owned backend container stop/start; existing Redis volume and network namespace retained'))),
    counters=fields(dict(before=COUNTERS,after=COUNTERS),dict(delta=COUNTERS)),
    resources=fields(dict(samples=COUNT,interval_seconds=literal(5),
        peak=roles(fields(dict(docker_memory_bytes=COUNT,cgroup_memory_bytes=COUNT,pids=COUNT,cpu_percent=number))),
        scope=literal('sampled Docker CLI and exact cgroup-v2 readbacks; observer exec processes contribute to usage; no leak proof')),
        dict(before=RESOURCE_POINT,after=RESOURCE_POINT,sampling_diagnostic=DIAGNOSTIC)),
    soak=SOAK,failure=FAILURE,last_states=roles(STATE),state_readback_incomplete=BOOL))

# Only public candidate source paths may appear in an uploaded hash map. This is
# a literal allowlist, not arbitrary receipt strings or candidate code execution.
SOURCE_PATHS = frozenset((
    'LICENSE',
    'deploy/spring-ingress/Dockerfile.backend',
    'deploy/spring-ingress/Dockerfile.backend.dockerignore',
    'deploy/spring-ingress/Dockerfile.gateway',
    'deploy/spring-ingress/Dockerfile.gateway.dockerignore',
    'deploy/spring-ingress/Dockerfile.redis',
    'deploy/spring-ingress/Dockerfile.redis.dockerignore',
    'deploy/spring-ingress/README.md',
    'deploy/spring-ingress/backend-entrypoint.sh',
    'deploy/spring-ingress/base-images.json',
    'deploy/spring-ingress/compose.json',
    'deploy/spring-ingress/probe.py',
    'deploy/spring-ingress/uv.requirements.txt',
    'examples/spring-ingress/backend/.gitignore',
    'examples/spring-ingress/backend/pom.xml',
    'examples/spring-ingress/backend/src/main/java/io/appguard/example/BackendCounters.java',
    'examples/spring-ingress/backend/src/main/java/io/appguard/example/BackendMain.java',
    'examples/spring-ingress/backend/src/main/java/io/appguard/example/BackendSettings.java',
    'examples/spring-ingress/backend/src/test/java/io/appguard/example/BackendTest.java',
    'examples/spring-ingress/ingress.py',
    'scripts/qualification/spring_containers.py',
    'scripts/qualification/spring_ingress.py',
    'sdk/python/LICENSE',
    'sdk/python/README.md',
    'sdk/python/pyproject.toml',
    'sdk/python/src/appguard/__init__.py',
    'sdk/python/src/appguard/asgi.py',
    'sdk/python/src/appguard/audit.py',
    'sdk/python/src/appguard/canonical.py',
    'sdk/python/src/appguard/crypto.py',
    'sdk/python/src/appguard/django.py',
    'sdk/python/src/appguard/enrollment.py',
    'sdk/python/src/appguard/enrollment_store.py',
    'sdk/python/src/appguard/enrollment_types.py',
    'sdk/python/src/appguard/fastapi.py',
    'sdk/python/src/appguard/flask.py',
    'sdk/python/src/appguard/policy.py',
    'sdk/python/src/appguard/providers/__init__.py',
    'sdk/python/src/appguard/providers/apple.py',
    'sdk/python/src/appguard/providers/apple_app_attestation_root.pem',
    'sdk/python/src/appguard/providers/apple_assertions.py',
    'sdk/python/src/appguard/providers/apple_enrollment.py',
    'sdk/python/src/appguard/providers/apple_lifecycle.py',
    'sdk/python/src/appguard/providers/apple_receipt_root_g3.pem',
    'sdk/python/src/appguard/providers/apple_receipts.py',
    'sdk/python/src/appguard/providers/apple_store.py',
    'sdk/python/src/appguard/providers/google.py',
    'sdk/python/src/appguard/providers/google_oauth.py',
    'sdk/python/src/appguard/redis.py',
    'sdk/python/src/appguard/replay.py',
    'sdk/python/src/appguard/types.py',
    'sdk/python/src/appguard/uvicorn.py',
    'sdk/python/src/appguard/verify.py',
    'sdk/python/src/appguard/wire.py',
    'sdk/python/uv.lock',
    'sdk/spring-boot/pom.xml',
    'sdk/spring-boot/src/main/java/io/appguard/AppGuardAutoConfiguration.java',
    'sdk/spring-boot/src/main/java/io/appguard/AppGuardFilter.java',
    'sdk/spring-boot/src/main/java/io/appguard/AppGuardProperties.java',
    'sdk/spring-boot/src/main/java/io/appguard/AuditEvent.java',
    'sdk/spring-boot/src/main/java/io/appguard/AuditException.java',
    'sdk/spring-boot/src/main/java/io/appguard/AuditUnavailableException.java',
    'sdk/spring-boot/src/main/java/io/appguard/BufferedRequest.java',
    'sdk/spring-boot/src/main/java/io/appguard/Canonical.java',
    'sdk/spring-boot/src/main/java/io/appguard/Header.java',
    'sdk/spring-boot/src/main/java/io/appguard/Identity.java',
    'sdk/spring-boot/src/main/java/io/appguard/IdentityResolver.java',
    'sdk/spring-boot/src/main/java/io/appguard/JsonAuditSink.java',
    'sdk/spring-boot/src/main/java/io/appguard/KeyRecord.java',
    'sdk/spring-boot/src/main/java/io/appguard/KeyResolver.java',
    'sdk/spring-boot/src/main/java/io/appguard/LocalReplayStore.java',
    'sdk/spring-boot/src/main/java/io/appguard/ParsedSignature.java',
    'sdk/spring-boot/src/main/java/io/appguard/Policy.java',
    'sdk/spring-boot/src/main/java/io/appguard/PolicyContext.java',
    'sdk/spring-boot/src/main/java/io/appguard/PolicyDecision.java',
    'sdk/spring-boot/src/main/java/io/appguard/PolicyEngine.java',
    'sdk/spring-boot/src/main/java/io/appguard/PolicyException.java',
    'sdk/spring-boot/src/main/java/io/appguard/PolicyValidation.java',
    'sdk/spring-boot/src/main/java/io/appguard/RedisReplayStore.java',
    'sdk/spring-boot/src/main/java/io/appguard/ReplayScope.java',
    'sdk/spring-boot/src/main/java/io/appguard/ReplayStore.java',
    'sdk/spring-boot/src/main/java/io/appguard/ReplayValidation.java',
    'sdk/spring-boot/src/main/java/io/appguard/RequestInput.java',
    'sdk/spring-boot/src/main/java/io/appguard/SignatureParameters.java',
    'sdk/spring-boot/src/main/java/io/appguard/VerificationException.java',
    'sdk/spring-boot/src/main/java/io/appguard/VerificationResult.java',
    'sdk/spring-boot/src/main/java/io/appguard/Verifier.java',
    'sdk/spring-boot/src/main/java/io/appguard/Wire.java',
    'sdk/spring-boot/src/main/resources/META-INF/LICENSE',
    'sdk/spring-boot/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports',
))


def source_path(value):
    require(type(value) is str and value in SOURCE_PATHS)


def runtime_platform(pid1):
    row = dict(image_id=IMAGE,os=literal('linux'),architecture=enum('amd64','arm64'))
    if pid1: row['pid1_elf_machine'] = integer(62,183)
    shape = fields(dict(schema=literal(1),platform=enum('linux/amd64','linux/arm64'),
        host_machine=nullable(enum('x86_64','aarch64')),daemon_architecture=nullable(enum('amd64','arm64')),
        images=mapping(enum(*ROLES),fields(row),maximum=3),verified=BOOL))
    def check(value):
        shape(value)
        arch = value['platform'].split('/')[1]; machine = 'x86_64' if arch == 'amd64' else 'aarch64'
        require(value['host_machine'] in (None,machine) and value['daemon_architecture'] in (None,arch))
        for item in value['images'].values():
            require(item['architecture'] == arch)
            if pid1: require(item['pid1_elf_machine'] == (62 if arch == 'amd64' else 183))
        if value['verified']:
            require(value['host_machine'] == machine and value['daemon_architecture'] == arch and set(value['images']) == set(ROLES))
    return check


RECEIPT = fields(dict(schema=literal(1),evidence_class=literal('owned_container_deployment'),
    profile=literal('spring-loopback-mtls-containers-v1'),observed_at=UTC,candidate_commit=COMMIT,
    source_matches_commit=BOOL,source_sha256=mapping(source_path,SHA,1),checks=fields({key:BOOL for key in CHECKS}),
    release_ready=literal(False),external_approval=literal(False),technical_verification=BOOL,cleanup=BOOL,
    phase=enum('certificates','daemon_and_builder','image_build','startup_compose_up','startup_runtime_inspection',
        'startup_volume_inspection','startup_readiness','startup_effective_restrictions','signed_requests',
        'redis_restart','backend_bypass','upload_deadline','malformed_framing','sustained_containers','completed'),
    limitations=literal(list(RECEIPT_LIMITATIONS)),containers=fields(dict(container_ids=roles(SHA),image_ids=roles(IMAGE),
        gateway_port=integer(1,65535),logging=roles(fields(dict(driver=literal('local'),compress=literal(False),
            max_files=literal(1),max_size_bytes=literal(1048576))))))),
    dict(resolved_compose_sha256=SHA,docker_server_version=VERSION,runtime_versions=fields(dict(python=VERSION,java=VERSION,redis=VERSION,
        installers_absent=fields({key:BOOL for key in ('pip','setuptools','wheel','ensurepip')}),python_inventory_matches_build=BOOL,
        python_required_packages=fields({key:VERSION for key in ('cryptography','h11','redis','uvicorn')}))),
        redis_restart=fields(dict(outage_status=literal(503),outage_seconds=number,recovery_seconds=number,recovery_attempts=COUNT,
            run_identity_changed=BOOL,aof_enabled=BOOL,appendfsync=literal('always'),original_replay_status=literal(403),
            scope=literal('routine owned Redis container stop/start; no power-loss or disk-failure claim'))),
        backend_counters=COUNTERS,resource_limits=roles(fields({key:COUNT for key in ('Memory','MemorySwap','NanoCpus','PidsLimit')})),
        operational=OPERATIONAL,startup_diagnostics=STARTUP,runtime_platform=runtime_platform(True)))
COVERAGE = fields(dict(os_inventory=BOOL,os_package_count=COUNT,application_package_count=COUNT,application_inventory=nullable(BOOL),
    native_binary_coverage=literal(False),coverage_complete=literal(False)))
STATUS1 = fields(dict(schema=literal(1),evidence_class=literal('owned_container_image_scan'),release_ready=literal(False),
    automated_checks_passed=BOOL,reason=enum('container_scan_unverified','findings_present','inventory_unverified','local_images_checked'),
    qualification_sha256=SHA,images=mapping(enum(*ROLES),fields(dict(image_id=IMAGE,report_sha256=SHA,vulnerabilities=COUNT,coverage=COVERAGE)),maximum=3),
    scanners=literal(['vuln']),vulnerabilities=nullable(COUNT),secrets=literal(None),coverage_complete=literal(False),
    native_binary_coverage=literal(False),complete_resolved_graph=literal(False),coverage_passed=BOOL,
    coverage_limitations=literal(list(COVERAGE_LIMITATIONS))))
# Schema 2 is independently validated here. Never import scanner/candidate code.
TRIVY_ARCHIVES = {
    'Linux-x86_64': 'c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0',
    'Darwin-arm64': '11a9b6cd2752011b54f01ea4bd0dbfa9f0c41dc6538d5a3f9d23955f471bf4e5',
    'Linux-aarch64': 'e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f',
}
FINDING_VERSION = pattern(r'[A-Za-z0-9][A-Za-z0-9._+~:!*-]*',200)
FINDING = fields(dict(vulnerability_id=pattern(r'[A-Z][A-Z0-9]{1,19}(?:-[A-Za-z0-9]+){1,9}',200),
    package=pattern(r'(?:[A-Za-z0-9][A-Za-z0-9._+:-]*|@[A-Za-z0-9._-]+/[A-Za-z0-9._-]+)',200),
    installed_version=FINDING_VERSION,fixed_versions=sequence(FINDING_VERSION,32),
    severity=enum('UNKNOWN','LOW','MEDIUM','HIGH','CRITICAL'),source_class=enum('os-pkgs','lang-pkgs'),
    package_type=pattern(r'[a-z][a-z0-9-]{0,39}',40),occurrence_sha256=SHA))
SCANNER = fields(dict(name=literal('trivy'),version=literal('0.76.1'),platform=enum(*TRIVY_ARCHIVES),
    archive_sha256=SHA,executable_sha256=SHA))


def timestamp(value):
    UTC(value)
    # Validate the calendar and compare all nine fractional digits, rather than
    # silently truncating nanoseconds to Python datetime's microseconds.
    datetime.strptime(value[:19],'%Y-%m-%dT%H:%M:%S')
    fraction=value[20:-1] if '.' in value else ''
    return value[:19],fraction.ljust(9,'0')


def database(schema):
    shape=fields(dict(schema=literal(schema),metadata_sha256=SHA,database_sha256=SHA,
        updated_at=UTC,next_update=UTC,downloaded_at=UTC))
    def check(value):
        shape(value)
        updated=timestamp(value['updated_at'])
        require(updated<=timestamp(value['downloaded_at']) and updated<timestamp(value['next_update']))
    return check


STATUS2 = fields(dict(schema=literal(2),evidence_class=literal('owned_container_image_scan'),release_ready=literal(False),
    automated_checks_passed=BOOL,reason=enum('container_scan_unverified','findings_present','inventory_unverified','local_images_checked'),
    qualification_sha256=SHA,images=mapping(enum(*ROLES),fields(dict(image_id=IMAGE,report_sha256=SHA,vulnerabilities=COUNT,
        coverage=COVERAGE,findings=sequence(FINDING,1024),finding_details_complete=BOOL)),maximum=3),
    scanners=literal(['vuln']),vulnerabilities=nullable(COUNT),secrets=literal(None),coverage_complete=literal(False),
    native_binary_coverage=literal(False),complete_resolved_graph=literal(False),coverage_passed=BOOL,
    coverage_limitations=literal(list(COVERAGE_LIMITATIONS)),scanner=nullable(SCANNER),
    databases=nullable(fields(dict(vulnerability=database(2),java=database(1)))),finding_details_complete=BOOL),
    dict(runtime_platform=runtime_platform(False)))


def STATUS(value):
    require(type(value) is dict and type(value.get('schema')) is int)
    if value['schema']==1:
        STATUS1(value)
        return
    STATUS2(value)
    images=value['images']; full=set(images)==set(ROLES)
    if value['scanner'] is not None:
        scanner=value['scanner']
        require(scanner['archive_sha256']==TRIVY_ARCHIVES[scanner['platform']])
        if scanner['platform'] == 'Linux-aarch64':
            require('runtime_platform' in value and value['runtime_platform']['platform'] == 'linux/arm64')
        if 'runtime_platform' in value:
            machine = 'x86_64' if value['runtime_platform']['platform'] == 'linux/amd64' else 'aarch64'
            require(scanner['platform'] == 'Linux-' + machine)
    if 'runtime_platform' in value and value['automated_checks_passed']: require(value['runtime_platform']['verified'])
    total=sum(row['vulnerabilities'] for row in images.values())
    require(value['vulnerabilities'] is None or (full and value['vulnerabilities']==total))
    require(full or value['vulnerabilities'] is None)
    for row in images.values():
        require(len(row['findings'])==row['vulnerabilities'] if row['finding_details_complete'] else not row['findings'])
    provenance=value['scanner'] is not None and value['databases'] is not None
    complete=full and provenance and all(row['finding_details_complete'] for row in images.values())
    if value['reason']=='container_scan_unverified': require(not value['finding_details_complete'])
    if value['finding_details_complete']:
        require(complete and value['vulnerabilities']==total)
    elif complete:
        # A later integrity failure can invalidate otherwise complete rows.
        require(value['reason']=='container_scan_unverified')
    if not provenance:
        require(value['reason']=='container_scan_unverified' and not value['finding_details_complete'])
    coverage=full and all(row['coverage']['os_inventory'] and
        (role=='redis' or row['coverage']['application_inventory'] is True) for role,row in images.items())
    if value['coverage_passed']: require(coverage)
    if value['automated_checks_passed']:
        require(value['finding_details_complete'] and value['vulnerabilities']==0 and value['coverage_passed']
            and value['reason']=='local_images_checked')
    if value['reason']=='local_images_checked': require(value['automated_checks_passed'])
    if value['reason']=='findings_present': require(value['vulnerabilities'] is not None and total>0)
    if value['reason']=='inventory_unverified':
        require(value['vulnerabilities']==0 and not value['coverage_passed'] and not value['automated_checks_passed'])


METADATA = fields(dict(repository=literal('bonjin-app/appguard'),candidate_commit=COMMIT,run_id=integer(1),run_attempt=integer(1),
    event=enum('push','workflow_dispatch','pull_request'),head_branch=pattern(r'[A-Za-z0-9][A-Za-z0-9._/-]{0,254}',255),
    workflow_path=literal('.github/workflows/container-readiness.yml')))


def parse(raw):
    def pairs(items):
        result={}
        for key,value in items:
            require(key not in result); result[key]=value
        return result
    def invalid(value): raise ValueError('container_evidence_unverified')
    result=json.loads(raw,object_pairs_hook=pairs,parse_constant=invalid)
    budget=[0]
    def bound(value,depth=0):
        budget[0]+=1; require(depth<=32 and budget[0]<=200000)
        if type(value) is dict:
            for key,item in value.items(): require(len(key)<=4096); bound(item,depth+1)
        elif type(value) is list:
            for item in value: bound(item,depth+1)
        elif type(value) is str: require(len(value)<=4096)
    bound(result)
    return result


def canonical(path):
    path=Path(path).absolute()
    require(path == path.resolve(strict=True))
    return path


def stamp(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def read_pin(path):
    path=canonical(path); before=path.lstat()
    require(stat.S_ISREG(before.st_mode) and 0<before.st_size<=MAX_BYTES)
    descriptor=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
    with os.fdopen(descriptor,'rb') as stream:
        require(stamp(before)==stamp(os.fstat(stream.fileno())))
        raw=stream.read(MAX_BYTES+1)
        require(len(raw)==before.st_size and stamp(before)==stamp(os.fstat(stream.fileno())))
    require(stamp(before)==stamp(path.lstat()) and canonical(path)==path)
    return dict(raw=raw,stamp=stamp(before),sha256=hashlib.sha256(raw).hexdigest())


def verify_pin(path,pin):
    current=read_pin(path)
    require(all(current[key]==pin[key] for key in ('stamp','sha256')))


class Publication:
    """Descriptor-owned private staging and exclusive publication, never overwrite."""
    def __init__(self,output):
        self.output=output; self.name='.appguard-binding-'+secrets.token_hex(16)
        self.parent_fd=self.stage_fd=None; self.published=False; self.pins={}
    def __enter__(self):
        self.parent_fd=os.open(self.output.parent,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:
            self.check_parent(); os.mkdir(self.name,0o700,dir_fd=self.parent_fd)
            self.stage_fd=os.open(self.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=self.parent_fd)
            self.check_stage()
        except BaseException:
            if self.stage_fd is not None:
                try:
                    held=os.fstat(self.stage_fd)
                    named=os.stat(self.name,dir_fd=self.parent_fd,follow_symlinks=False)
                    if held.st_uid==os.getuid() and (named.st_dev,named.st_ino)==(held.st_dev,held.st_ino):
                        os.rmdir(self.name,dir_fd=self.parent_fd)
                except OSError: pass
                finally: os.close(self.stage_fd)
            os.close(self.parent_fd); raise
        return self
    def check_parent(self):
        parent=canonical(self.output.parent); current=parent.stat(); held=os.fstat(self.parent_fd)
        require((current.st_dev,current.st_ino)==(held.st_dev,held.st_ino))
        require(stat.S_ISDIR(held.st_mode) and held.st_uid==os.getuid() and held.st_mode & 0o022==0)
    def check_stage(self):
        held=os.fstat(self.stage_fd)
        require(stat.S_ISDIR(held.st_mode) and held.st_uid==os.getuid() and stat.S_IMODE(held.st_mode)==0o700)
    def check_output(self):
        self.check_parent(); named=os.stat(self.output.name,dir_fd=self.parent_fd,follow_symlinks=False); held=os.fstat(self.stage_fd)
        require(stat.S_ISDIR(named.st_mode) and (named.st_dev,named.st_ino)==(held.st_dev,held.st_ino))
    def write(self,name,raw):
        self.check_stage()
        require(name in ('receipt.json','image-status.json','binding.json'))
        descriptor=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=self.stage_fd)
        with os.fdopen(descriptor,'wb') as stream:
            stream.write(raw); stream.flush(); os.fsync(stream.fileno())
            self.pins[name]=(stamp(os.fstat(stream.fileno())),hashlib.sha256(raw).hexdigest())
        self.verify_files()
    def verify_files(self):
        self.check_stage()
        require(set(os.listdir(self.stage_fd))==set(self.pins))
        for name,(identity,digest) in self.pins.items():
            descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK,dir_fd=self.stage_fd)
            with os.fdopen(descriptor,'rb') as stream:
                require(identity==stamp(os.fstat(stream.fileno())))
                raw=stream.read(MAX_BYTES+1)
                require(identity==stamp(os.fstat(stream.fileno())) and hashlib.sha256(raw).hexdigest()==digest)
            require(identity==stamp(os.stat(name,dir_fd=self.stage_fd,follow_symlinks=False)))
        require(set(os.listdir(self.stage_fd))==set(self.pins))
    def publish(self):
        require(set(self.pins)=={'receipt.json','image-status.json','binding.json'})
        self.verify_files()
        self.check_parent(); named=os.stat(self.name,dir_fd=self.parent_fd,follow_symlinks=False); held=os.fstat(self.stage_fd)
        require(stat.S_ISDIR(named.st_mode) and (named.st_dev,named.st_ino)==(held.st_dev,held.st_ino))
        libc=ctypes.CDLL(None,use_errno=True)
        require(sys.platform in ('linux','darwin'))
        rename=libc.renameat2 if sys.platform=='linux' else libc.renameatx_np
        rename.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]; rename.restype=ctypes.c_int
        require(rename(self.parent_fd,os.fsencode(self.name),self.parent_fd,os.fsencode(self.output.name),1 if sys.platform=='linux' else 4)==0)
        self.published=True; self.check_output(); self.verify_files()
    def __exit__(self,kind,value,traceback):
        try:
            if kind is not None or not self.published:
                # Only descriptor-owned entries; never recurse into an injected directory.
                for name in os.listdir(self.stage_fd):
                    try: os.unlink(name,dir_fd=self.stage_fd)
                    except (FileNotFoundError,IsADirectoryError): pass
                name=self.output.name if self.published else self.name
                try:
                    named=os.stat(name,dir_fd=self.parent_fd,follow_symlinks=False); held=os.fstat(self.stage_fd)
                    if (named.st_dev,named.st_ino)==(held.st_dev,held.st_ino): os.rmdir(name,dir_fd=self.parent_fd)
                except FileNotFoundError: pass
        finally:
            os.close(self.stage_fd); os.close(self.parent_fd)


def stage(receipt,image_status,output,**metadata):
    METADATA(metadata)
    require(all(part not in ('','.', '..') for part in metadata['head_branch'].split('/')))
    receipt=canonical(receipt); image_status=canonical(image_status)
    output=Path(output).absolute(); require(output.name not in ('','.','..'))
    require(output.parent==canonical(output.parent) and not output.exists() and not output.is_symlink())
    rp=read_pin(receipt); sp=read_pin(image_status)
    r=parse(rp['raw']); s=parse(sp['raw']); RECEIPT(r); STATUS(s)
    require(r['candidate_commit']==metadata['candidate_commit'] and s['qualification_sha256']==rp['sha256'])
    require(all(record['image_id']==r['containers']['image_ids'][role] for role,record in s['images'].items()))
    require(('runtime_platform' in r) == ('runtime_platform' in s))
    if 'runtime_platform' in r:
        rpblock,spblock = r['runtime_platform'],s['runtime_platform']
        require(rpblock['platform'] == spblock['platform'])
        for value in (rpblock,spblock):
            require(all(row['image_id'] == r['containers']['image_ids'][role] for role,row in value['images'].items()))
        if r['technical_verification']: require(rpblock['verified'])
        if spblock['verified']: require(rpblock['verified'])
    binding=dict(schema=1,evidence_class='owned_container_ci_binding',**metadata,
        receipt_sha256=rp['sha256'],image_status_sha256=sp['sha256'])
    raw=json.dumps(binding,sort_keys=True,separators=(',',':')).encode()+b'\n'
    with Publication(output) as publication:
        publication.write('receipt.json',rp['raw']); publication.write('image-status.json',sp['raw']); publication.write('binding.json',raw)
        verify_pin(receipt,rp); verify_pin(image_status,sp); publication.verify_files(); publication.publish()
        verify_pin(receipt,rp); verify_pin(image_status,sp); publication.verify_files(); publication.check_output()
    return dict(schema=1,evidence_class='owned_container_ci_staging',staged=True,release_ready=False,
        receipt_sha256=rp['sha256'],image_status_sha256=sp['sha256'],binding_sha256=hashlib.sha256(raw).hexdigest())


class Parser(argparse.ArgumentParser):
    def error(self,message): raise ValueError('container_evidence_unverified')


def main(argv=None):
    try:
        parser=Parser(description=__doc__)
        for name in ('receipt','image-status','output','repository','candidate-commit','run-id','run-attempt','event','head-branch','workflow-path'):
            parser.add_argument('--'+name,required=True)
        args=vars(parser.parse_args(argv))
        for key in ('run_id','run_attempt'):
            require(re.fullmatch(r'[1-9][0-9]{0,15}',args[key]) is not None); args[key]=int(args[key])
        def cancel(signum,frame): raise KeyboardInterrupt()
        old=signal.signal(signal.SIGTERM,cancel)
        try: result=stage(**args)
        finally: signal.signal(signal.SIGTERM,old)
        print(json.dumps(result,sort_keys=True)); return 0
    except (ValueError,OSError,TypeError,KeyError,RecursionError,UnicodeError,KeyboardInterrupt,AttributeError):
        print(json.dumps(dict(schema=1,evidence_class='owned_container_ci_staging',staged=False,
            release_ready=False,reason='container_evidence_unverified'),sort_keys=True)); return 2


if __name__=='__main__':
    raise SystemExit(main())
