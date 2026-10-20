import 'dart:convert';
import 'package:appguard_flutter/appguard_flutter.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('io.appguard/client');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final client = AppGuard();
  final bytes = Uint8List.fromList([0, 255, 128, 13, 10, 65]);
  Future<PreparedRequest> prepare() => client.prepare(
      alias: 'installation',
      hardwareRequirement: HardwareRequirement.any,
      origin: 'https://example.com',
      method: 'POST',
      target: '/a%2Fb?',
      body: bytes,
      contentType: 'application/octet-stream',
      authorization: 'Bearer secret-token',
      appId: 'app',
      keyId: 'key',
      created: 123,
      expires: 124,
      nonce: 'AAAAAAAAAAAAAAAAAAAAAA');
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));
  test('exact binary target and ordered header round trip', () async {
    final headers = [
      ['Authorization', 'Bearer secret-token'],
      ['Content-Type', 'application/octet-stream'],
      ['x-appguard-app-id', 'app'],
      ['x-appguard-key-id', 'key'],
      ['Content-Digest', 'sha-256=:test:'],
      ['Signature', 'sig']
    ];
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.method, 'invoke');
      expect((call.arguments as Map).keys,
          unorderedEquals(['operation', 'payload']));
      expect(call.arguments['operation'], 'prepare');
      final p = jsonDecode(call.arguments['payload'] as String);
      expect(p, {
        'alias': 'installation',
        'hardwareRequirement': 'any',
        'origin': 'https://example.com',
        'method': 'POST',
        'target': '/a%2Fb?',
        'bodyBase64': base64Encode(bytes),
        'contentType': 'application/octet-stream',
        'authorization': 'Bearer secret-token',
        'appId': 'app',
        'keyId': 'key',
        'created': 123,
        'expires': 124,
        'nonce': 'AAAAAAAAAAAAAAAAAAAAAA'
      });
      return jsonEncode({
        'ok': true,
        'result': {
          'origin': p['origin'],
          'method': p['method'],
          'target': p['target'],
          'bodyBase64': p['bodyBase64'],
          'keyId': p['keyId'],
          'headers': headers
        }
      });
    });
    final r = await prepare();
    expect(r.target, '/a%2Fb?');
    expect(r.body, bytes);
    expect(r.headers, headers);
    expect(r.origin, 'https://example.com');
  });
  test('public key maps hardware explicitly', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.arguments['operation'], 'publicKey');
      expect(jsonDecode(call.arguments['payload']),
          {'alias': 'a', 'hardwareRequirement': 'strongbox'});
      return jsonEncode({
        'ok': true,
        'result': {'publicKeyPem': 'PEM', 'backing': 'STRONGBOX'}
      });
    });
    final r = await client.publicKey(
        alias: 'a', hardwareRequirement: HardwareRequirement.strongbox);
    expect(r.publicKeyPem, 'PEM');
    expect(r.backing, 'STRONGBOX');
  });
  test('enrollment challenge and expected bindings stay distinct', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.arguments['operation'], 'enrollmentProof');
      final p = jsonDecode(call.arguments['payload']);
      expect(p['challenge'], {
        'appId': 'a',
        'origin': 'https://example.com',
        'subject': 's',
        'keyId': 'k',
        'publicKeySha256': 'h',
        'nonce': 'n',
        'expires': 42
      });
      expect(p['expectedSubject'], 'expected');
      return jsonEncode({
        'ok': true,
        'result': {
          'proofBase64': 'AA==',
          'clientDataHashBase64': 'AQ==',
          'googleRequestHash': 'Ag'
        }
      });
    });
    final r = await client.enrollmentProof(
        alias: 'a',
        hardwareRequirement: HardwareRequirement.hardware,
        challenge: const EnrollmentChallenge(
            appId: 'a',
            origin: 'https://example.com',
            subject: 's',
            keyId: 'k',
            publicKeySha256: 'h',
            nonce: 'n',
            expires: 42),
        expectedAppId: 'a',
        expectedOrigin: 'https://example.com',
        expectedSubject: 'expected',
        expectedKeyId: 'k');
    expect(r.proofBase64, 'AA==');
    expect(r.clientDataHashBase64, 'AQ==');
    expect(r.googleRequestHash, 'Ag');
  });
  for (final code in [
    'APPGUARD_INVALID_INPUT',
    'APPGUARD_KEY_UNAVAILABLE',
    'APPGUARD_UNSUPPORTED',
    'APPGUARD_OPERATION_FAILED'
  ]) {
    test('fixed native error $code', () async {
      messenger.setMockMethodCallHandler(
          channel,
          (_) async => jsonEncode({
                'ok': false,
                'error': {'code': code, 'message': 'secret-token'}
              }));
      await expectLater(
          prepare(),
          throwsA(isA<AppGuardException>()
              .having((e) => e.toString(), 'code', code)));
    });
  }
  test('missing plugin explicit', () async {
    await expectLater(
        prepare(),
        throwsA(isA<AppGuardException>()
            .having((e) => e.code, 'code', 'APPGUARD_NATIVE_UNAVAILABLE')));
  });
  test('platform exceptions redact all text and details', () async {
    messenger.setMockMethodCallHandler(
        channel,
        (_) async => throw PlatformException(
            code: 'Bearer secret-token',
            message: 'secret-token',
            details: 'private-key'));
    await expectLater(
        prepare(),
        throwsA(isA<AppGuardException>()
            .having((e) => e.toString(), 'code', 'APPGUARD_OPERATION_FAILED')));
  });
  for (final response in [
    null,
    42,
    'not-json',
    '{"ok":"true","result":{}}',
    '{"ok":false,"error":{"code":"secret-token"}}',
    '{"ok":true,"result":{"origin":42}}',
    '{"ok":true,"result":{"origin":"https://example.com","method":"POST","target":"/a%2Fb?","bodyBase64":"%%%","keyId":"key","headers":[]}}'
  ]) {
    test('invalid native response ${response.runtimeType} ${response.hashCode}',
        () async {
      messenger.setMockMethodCallHandler(channel, (_) async => response);
      await expectLater(
          prepare(),
          throwsA(isA<AppGuardException>()
              .having((e) => e.code, 'code', 'APPGUARD_OPERATION_FAILED')));
    });
  }
  test('oversized body rejects before native call', () async {
    messenger.setMockMethodCallHandler(
        channel, (_) async => fail('must not invoke native'));
    await expectLater(
        client.prepare(
            alias: 'a',
            hardwareRequirement: HardwareRequirement.any,
            origin: 'https://example.com',
            method: 'POST',
            target: '/',
            body: Uint8List(1048577),
            contentType: 'x',
            authorization: 'Bearer secret',
            appId: 'a',
            keyId: 'k',
            created: 1,
            expires: 2,
            nonce: 'n'),
        throwsA(isA<AppGuardException>()
            .having((e) => e.code, 'code', 'APPGUARD_INVALID_INPUT')));
  });
}
