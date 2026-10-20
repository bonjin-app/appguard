import 'dart:convert';
import 'dart:io';
import 'package:appguard_flutter/appguard_flutter.dart';
import 'package:flutter/services.dart';
import 'package:flutter_test/flutter_test.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();
  const channel = MethodChannel('io.appguard/client');
  final messenger =
      TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger;
  final client = AppGuard();
  final cases = (jsonDecode(File('../../conformance/v0/local-risk-bridge.json')
      .readAsStringSync()) as Map)['reports'] as List;
  final good = cases.first['report'];
  Matcher error(String code) => throwsA(
      isA<AppGuardException>().having((e) => e.code, 'fixed code', code));
  void response(Object? value) =>
      messenger.setMockMethodCallHandler(channel, (_) async => value);
  tearDown(() => messenger.setMockMethodCallHandler(channel, null));
  for (final vector in cases) {
    test('shared report ${vector['id']}', () async {
      response(jsonEncode({'ok': true, 'result': vector['report']}));
      if (vector['valid'] == true) {
        final report = await client.scanLocalRisk();
        expect(report.schema, 'appguard-local-risk-v0');
        expect(report.platform, vector['report']['platform']);
        expect(report.checks.map((c) => {'code': c.code, 'state': c.state}),
            vector['report']['checks']);
        expect(report.riskSignals, vector['report']['riskSignals']);
        expect(() => report.checks.clear(), throwsUnsupportedError);
        expect(() => report.riskSignals.clear(), throwsUnsupportedError);
      } else {
        await expectLater(
            client.scanLocalRisk(), error('APPGUARD_OPERATION_FAILED'));
      }
    });
  }
  test('default scan sends only empty config', () async {
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(call.arguments, {'operation': 'scanLocalRisk', 'payload': '{}'});
      return jsonEncode({'ok': true, 'result': good});
    });
    await client.scanLocalRisk();
  });
  test('options snapshot and immutable collections', () async {
    final pins = ['a' * 64];
    final resources = {'assets/a.bin': 'b' * 64};
    final options = LocalRiskOptions(
        expectedAppId: 'co.example-App_1',
        androidSignerSha256: pins,
        protectedResources: resources);
    pins[0] = 'c' * 64;
    resources.clear();
    expect(() => options.androidSignerSha256!.clear(), throwsUnsupportedError);
    expect(() => options.protectedResources!.clear(), throwsUnsupportedError);
    messenger.setMockMethodCallHandler(channel, (call) async {
      expect(jsonDecode(call.arguments['payload']), {
        'expectedAppId': 'co.example-App_1',
        'androidSignerSha256': ['a' * 64],
        'protectedResources': {'assets/a.bin': 'b' * 64}
      });
      return jsonEncode({'ok': true, 'result': good});
    });
    await client.scanLocalRisk(options: options);
  });
  test('malformed options reject fixed input error before channel', () {
    messenger.setMockMethodCallHandler(
        channel, (_) async => fail('invalid reached channel'));
    final constructors = <LocalRiskOptions Function()>[
      () => LocalRiskOptions(expectedAppId: null),
      () => LocalRiskOptions(expectedAppId: 42),
      for (final id in ['', '-a', '한글', 'a\n', 'a' * 256])
        () => LocalRiskOptions(expectedAppId: id),
      for (final pins in [
        null,
        {},
        [null],
        [42],
        ['A' * 64],
        ['a' * 63],
        ['a' * 64, 'a' * 64],
        List.generate(9, (i) => i.toRadixString(16).padLeft(64, '0'))
      ])
        () => LocalRiskOptions(androidSignerSha256: pins),
      for (final resources in [
        null,
        [],
        {'a': 42},
        {'a': null},
        {42: 'a' * 64},
        {'a': 'A' * 64},
        for (final path in [
          '',
          '/a',
          'a/',
          'a//b',
          '.',
          '..',
          'a/../b',
          'a\\b',
          '한글',
          'a' * 129,
          '${'a' * 128}/${'b' * 128}'
        ])
          {path: 'a' * 64},
        {for (var i = 0; i < 9; i++) 'a$i': 'a' * 64}
      ])
        () => LocalRiskOptions(protectedResources: resources),
    ];
    for (final make in constructors) {
      expect(make, error('APPGUARD_INVALID_INPUT'));
    }
  });
  test('option boundaries and empty collections accepted', () async {
    response(jsonEncode({'ok': true, 'result': good}));
    await client.scanLocalRisk(
        options: LocalRiskOptions(
            expectedAppId: 'a' * 255,
            androidSignerSha256: [],
            protectedResources: {'${'a' * 128}/${'b' * 127}': 'f' * 64}));
    await client.scanLocalRisk(
        options: LocalRiskOptions(
            androidSignerSha256:
                List.generate(8, (i) => i.toRadixString(16).padLeft(64, '0')),
            protectedResources: {}));
  });
  test('scan output UTF8 bound and existing operation limit', () async {
    final base = jsonEncode({'ok': true, 'result': good});
    response(base + ' ' * (4096 - utf8.encode(base).length));
    await client.scanLocalRisk();
    response(base + ' ' * (4097 - utf8.encode(base).length));
    await expectLater(
        client.scanLocalRisk(), error('APPGUARD_OPERATION_FAILED'));
    response(base + 'é' * 1800);
    await expectLater(
        client.scanLocalRisk(), error('APPGUARD_OPERATION_FAILED'));
    response(jsonEncode({
      'ok': true,
      'result': {'publicKeyPem': 'P' * 9000, 'backing': 'SOFTWARE'}
    }));
    expect(
        (await client.publicKey(
                alias: 'a', hardwareRequirement: HardwareRequirement.any))
            .publicKeyPem
            .length,
        9000);
  });
  for (final code in [
    'APPGUARD_INVALID_INPUT',
    'APPGUARD_UNSUPPORTED',
    'APPGUARD_NATIVE_UNAVAILABLE',
    'APPGUARD_OPERATION_FAILED'
  ]) {
    test('scan preserves fixed $code', () async {
      response(jsonEncode({
        'ok': false,
        'error': {'code': code, 'message': 'PRIVATE'}
      }));
      await expectLater(client.scanLocalRisk(), error(code));
    });
  }
  test('scan unavailable has no clean fallback', () async {
    await expectLater(
        client.scanLocalRisk(), error('APPGUARD_NATIVE_UNAVAILABLE'));
  });
  test('scan redacts thrown native text', () async {
    messenger.setMockMethodCallHandler(
        channel,
        (_) async =>
            throw PlatformException(code: 'PRIVATE', message: 'PRIVATE'));
    await expectLater(
        client.scanLocalRisk(), error('APPGUARD_OPERATION_FAILED'));
  });
  for (final value in [null, 42, 'PRIVATE', '{"ok":true,"result":null}']) {
    test('scan malformed envelope ${value.runtimeType} ${value.hashCode}',
        () async {
      response(value);
      await expectLater(
          client.scanLocalRisk(), error('APPGUARD_OPERATION_FAILED'));
    });
  }
}
