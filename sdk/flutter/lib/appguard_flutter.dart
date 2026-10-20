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
      final json = jsonEncode(payload);
      if (utf8.encode(json).length > 1500000) {
        throw const AppGuardException(_invalid);
      }
      final response = await _channel.invokeMethod<Object?>(
          'invoke', {'operation': operation, 'payload': json});
      if (response is! String || utf8.encode(response).length > 1500000) {
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
