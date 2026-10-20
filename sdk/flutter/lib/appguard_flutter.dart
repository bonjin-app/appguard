/// Experimental AppGuard native bridge. No networking or cryptographic fallback.
library;

import 'dart:convert';
import 'package:flutter/services.dart';

/// A fixed, redacted error code; never includes native error details.
class AppGuardException implements Exception {
  final String code;
  const AppGuardException(this.code);
  @override
  String toString() => code;
}

enum HardwareRequirement { any, hardware, strongbox }

class PublicKey {
  final String publicKeyPem, backing;
  const PublicKey(this.publicKeyPem, this.backing);
}

/// Send these values unchanged, without redirects or target normalization.
class PreparedRequest {
  final String origin, method, target, bodyBase64, keyId;
  final List<List<String>> headers;
  PreparedRequest(this.origin, this.method, this.target, this.bodyBase64,
      this.keyId, List<List<String>> headers)
      : headers = List.unmodifiable(headers.map(List<String>.unmodifiable));
  Uint8List get body => base64Decode(bodyBase64);
}

/// Possession proof and hashes only, never a provider or server verdict.
class EnrollmentProof {
  final String proofBase64, clientDataHashBase64, googleRequestHash;
  const EnrollmentProof(
      this.proofBase64, this.clientDataHashBase64, this.googleRequestHash);
}

class EnrollmentChallenge {
  final String appId, origin, subject, keyId, publicKeySha256, nonce;
  final int expires;
  const EnrollmentChallenge(
      {required this.appId,
      required this.origin,
      required this.subject,
      required this.keyId,
      required this.publicKeySha256,
      required this.nonce,
      required this.expires});
  Map<String, Object> _json() => {
        'appId': appId,
        'origin': origin,
        'subject': subject,
        'keyId': keyId,
        'publicKeySha256': publicKeySha256,
        'nonce': nonce,
        'expires': expires
      };
}

/// Validated scan configuration. Omitted fields leave optional checks unconfigured.
/// Explicit nulls and malformed values throw APPGUARD_INVALID_INPUT.
final class LocalRiskOptions {
  static const _omitted = Object();
  final String? expectedAppId;
  final List<String>? androidSignerSha256;
  final Map<String, String>? protectedResources;

  factory LocalRiskOptions(
      {Object? expectedAppId = _omitted,
      Object? androidSignerSha256 = _omitted,
      Object? protectedResources = _omitted}) {
    const invalid = AppGuardException('APPGUARD_INVALID_INPUT');
    final idPattern = RegExp(r'^[A-Za-z0-9][A-Za-z0-9._-]*$');
    final pinPattern = RegExp(r'^[a-f0-9]{64}$');
    final component = RegExp(r'^[A-Za-z0-9_-][A-Za-z0-9._-]*$');
    bool exact(RegExp pattern, String value) =>
        pattern.stringMatch(value) == value;
    String? id;
    List<String>? pins;
    Map<String, String>? resources;
    if (!identical(expectedAppId, _omitted)) {
      if (expectedAppId is! String ||
          expectedAppId.length > 255 ||
          !exact(idPattern, expectedAppId)) throw invalid;
      id = expectedAppId;
    }
    if (!identical(androidSignerSha256, _omitted)) {
      if (androidSignerSha256 is! List || androidSignerSha256.length > 8)
        throw invalid;
      pins = [];
      for (final pin in androidSignerSha256) {
        if (pin is! String || !exact(pinPattern, pin) || pins.contains(pin))
          throw invalid;
        pins.add(pin);
      }
    }
    if (!identical(protectedResources, _omitted)) {
      if (protectedResources is! Map || protectedResources.length > 8)
        throw invalid;
      resources = {};
      for (final entry in protectedResources.entries) {
        final path = entry.key;
        final pin = entry.value;
        if (path is! String ||
            path.length > 256 ||
            path
                .split('/')
                .any((part) => part.length > 128 || !exact(component, part)) ||
            pin is! String ||
            !exact(pinPattern, pin)) throw invalid;
        resources[path] = pin;
      }
    }
    return LocalRiskOptions._(id, pins, resources);
  }
  LocalRiskOptions._(
      this.expectedAppId, List<String>? pins, Map<String, String>? resources)
      : androidSignerSha256 = pins == null ? null : List.unmodifiable(pins),
        protectedResources =
            resources == null ? null : Map.unmodifiable(resources);
  Map<String, Object> _json() => {
        if (expectedAppId != null) 'expectedAppId': expectedAppId!,
        if (androidSignerSha256 != null)
          'androidSignerSha256': androidSignerSha256!,
        if (protectedResources != null)
          'protectedResources': protectedResources!,
      };
}

/// An observation, never a clean-device or server verdict.
final class LocalRiskCheck {
  final String code, state;
  const LocalRiskCheck._(this.code, this.state);
}

final class LocalRiskReport {
  final String schema, platform;
  final List<LocalRiskCheck> checks;
  final List<String> riskSignals;
  LocalRiskReport._(this.schema, this.platform, List<LocalRiskCheck> checks,
      List<String> signals)
      : checks = List.unmodifiable(checks),
        riskSignals = List.unmodifiable(signals);
  static LocalRiskReport _decode(Map<String, dynamic> report) {
    const failed = AppGuardException('APPGUARD_OPERATION_FAILED');
    const android = [
      'debugger_attached',
      'debug_build',
      'root_artifact',
      'hook_artifact',
      'app_identity_mismatch',
      'app_signer_mismatch',
      'bundle_resource_mismatch'
    ];
    const ios = [
      'debugger_attached',
      'root_artifact',
      'hook_artifact',
      'app_identity_mismatch',
      'bundle_resource_mismatch'
    ];
    const states = {
      'detected',
      'not_observed',
      'unavailable',
      'not_configured'
    };
    final platform = report['platform'];
    final rawChecks = report['checks'];
    final rawSignals = report['riskSignals'];
    if (report.length != 4 ||
        report['schema'] != 'appguard-local-risk-v0' ||
        (platform != 'android' && platform != 'ios') ||
        rawChecks is! List ||
        rawSignals is! List) throw failed;
    final codes = platform == 'android' ? android : ios;
    if (rawChecks.length != codes.length) throw failed;
    final checks = <LocalRiskCheck>[];
    final signals = <String>[];
    var unavailable = false;
    for (var i = 0; i < codes.length; i++) {
      final check = rawChecks[i];
      if (check is! Map ||
          check.length != 2 ||
          check['code'] != codes[i] ||
          check['state'] is! String ||
          !states.contains(check['state']) ||
          (i < (platform == 'android' ? 4 : 3) &&
              check['state'] == 'not_configured')) throw failed;
      final state = check['state'] as String;
      checks.add(LocalRiskCheck._(codes[i], state));
      if (state == 'unavailable') unavailable = true;
      if (state == 'detected') {
        final signal = codes[i].startsWith('debug')
            ? 'debugger'
            : codes[i] == 'root_artifact'
                ? 'root'
                : codes[i] == 'hook_artifact'
                    ? 'hook'
                    : 'tamper';
        if (!signals.contains(signal)) signals.add(signal);
      }
    }
    if (unavailable) signals.add('local_checks_unavailable');
    if (rawSignals.length != signals.length) throw failed;
    for (var i = 0; i < signals.length; i++) {
      if (rawSignals[i] != signals[i]) throw failed;
    }
    return LocalRiskReport._(
        'appguard-local-risk-v0', platform as String, checks, signals);
  }
}

class AppGuard {
  static const _channel = MethodChannel('io.appguard/client');
  static const _failed = 'APPGUARD_OPERATION_FAILED';
  static const _invalid = 'APPGUARD_INVALID_INPUT';
  static const _codes = {
    _invalid,
    _failed,
    'APPGUARD_KEY_UNAVAILABLE',
    'APPGUARD_UNSUPPORTED',
    'APPGUARD_NATIVE_UNAVAILABLE'
  };

  Map<String, Object> _common(String alias, HardwareRequirement hardware) =>
      {'alias': alias, 'hardwareRequirement': hardware.name};

  Future<T> _invoke<T>(String operation, Map<String, Object> payload,
      T Function(Map<String, dynamic>) decode) async {
    try {
      final scan = operation == 'scanLocalRisk';
      final json = jsonEncode(payload);
      if (utf8.encode(json).length > (scan ? 8192 : 1500000)) {
        throw const AppGuardException(_invalid);
      }
      final response = await _channel.invokeMethod<Object?>(
          'invoke', {'operation': operation, 'payload': json});
      if (response is! String ||
          utf8.encode(response).length > (scan ? 4096 : 1500000)) {
        throw const AppGuardException(_failed);
      }
      final envelope = jsonDecode(response);
      if (envelope is! Map<String, dynamic> || envelope['ok'] is! bool) {
        throw const AppGuardException(_failed);
      }
      if (envelope['ok'] == false) {
        final error = envelope['error'];
        final code = error is Map ? error['code'] : null;
        throw AppGuardException(
            code is String && _codes.contains(code) ? code : _failed);
      }
      final result = envelope['result'];
      if (result is! Map<String, dynamic>)
        throw const AppGuardException(_failed);
      return decode(result);
    } on AppGuardException {
      rethrow;
    } on MissingPluginException {
      throw const AppGuardException('APPGUARD_NATIVE_UNAVAILABLE');
    } catch (_) {
      throw const AppGuardException(_failed);
    }
  }

  /// Runs native local observations off the platform UI thread. No fallback.
  Future<LocalRiskReport> scanLocalRisk({LocalRiskOptions? options}) =>
      _invoke('scanLocalRisk', options?._json() ?? {}, LocalRiskReport._decode);

  Future<PublicKey> publicKey(
          {required String alias,
          required HardwareRequirement hardwareRequirement}) =>
      _invoke(
          'publicKey',
          _common(alias, hardwareRequirement),
          (r) =>
              PublicKey(r['publicKeyPem'] as String, r['backing'] as String));

  Future<PreparedRequest> prepare(
      {required String alias,
      required HardwareRequirement hardwareRequirement,
      required String origin,
      required String method,
      required String target,
      required Uint8List body,
      required String contentType,
      required String authorization,
      required String appId,
      required String keyId,
      required int created,
      required int expires,
      required String nonce}) async {
    if (body.length > 1048576) throw const AppGuardException(_invalid);
    return _invoke('prepare', {
      ..._common(alias, hardwareRequirement),
      'origin': origin,
      'method': method,
      'target': target,
      'bodyBase64': base64Encode(body),
      'contentType': contentType,
      'authorization': authorization,
      'appId': appId,
      'keyId': keyId,
      'created': created,
      'expires': expires,
      'nonce': nonce
    }, (r) {
      final encoded = r['bodyBase64'] as String;
      final decoded = base64Decode(encoded);
      if (decoded.length > 1048576 || base64Encode(decoded) != encoded) {
        throw const AppGuardException(_failed);
      }
      final headers = (r['headers'] as List).map((pair) {
        if (pair is! List || pair.length != 2)
          throw const AppGuardException(_failed);
        return [pair[0] as String, pair[1] as String];
      }).toList();
      return PreparedRequest(r['origin'] as String, r['method'] as String,
          r['target'] as String, encoded, r['keyId'] as String, headers);
    });
  }

  Future<EnrollmentProof> enrollmentProof(
          {required String alias,
          required HardwareRequirement hardwareRequirement,
          required EnrollmentChallenge challenge,
          required String expectedAppId,
          required String expectedOrigin,
          required String expectedSubject,
          required String expectedKeyId}) =>
      _invoke(
          'enrollmentProof',
          {
            ..._common(alias, hardwareRequirement),
            'challenge': challenge._json(),
            'expectedAppId': expectedAppId,
            'expectedOrigin': expectedOrigin,
            'expectedSubject': expectedSubject,
            'expectedKeyId': expectedKeyId
          },
          (r) => EnrollmentProof(
              r['proofBase64'] as String,
              r['clientDataHashBase64'] as String,
              r['googleRequestHash'] as String));
}
