import XCTest
import Foundation
@testable import AppGuardApple

final class LocalRiskBridgeTests: XCTestCase {
    private let pinHash = String(repeating: "a", count: 64)

    // Dispatching through the key/clock path or omitting the operation breaks a read-only scan.
    func testDefaultNativeScanUsesNoKeyOrClockAndReturnsExactHostStates() throws {
        var keys = 0; var clocks = 0
        let bridge = NativeBridge(keyProvider: { _, _ in keys += 1; throw TestFailure.secret }, clock: { clocks += 1; return 0 })
        let result = try success(bridge.invoke(operation: "scanLocalRisk", payload: "{}"))
        XCTAssertEqual(result["schema"] as? String, "appguard-local-risk-v0")
        XCTAssertEqual(result["platform"] as? String, "ios")
        #if os(macOS)
        XCTAssertEqual(result["checks"] as? [[String: String]], [
            ["code": "debugger_attached", "state": "unavailable"],
            ["code": "root_artifact", "state": "unavailable"],
            ["code": "hook_artifact", "state": "unavailable"],
            ["code": "app_identity_mismatch", "state": "not_configured"],
            ["code": "bundle_resource_mismatch", "state": "not_configured"]])
        XCTAssertEqual(result["riskSignals"] as? [String], ["local_checks_unavailable"])
        #endif
        XCTAssertEqual(keys, 0); XCTAssertEqual(clocks, 0)
    }

    // Wire serialization must retain all four states, exact codes and derived signal order.
    func testConfiguredScanMapsOnlyValidatedConfigurationAndPreservesReport() throws {
        let probe = BridgeRiskProbe()
        var received: LocalRiskConfiguration?; var scans = 0
        let bridge = makeBridge { config in
            received = config; scans += 1
            return LocalRiskScanner(probe: probe).scan(configuration: config)
        }
        let payload = try json(["expectedAppId": "com.example.app", "androidSignerSha256": [], "protectedResources": ["Assets/check.bin": pinHash]])
        let text = bridge.invoke(operation: "scanLocalRisk", payload: payload)
        let result = try success(text)
        XCTAssertEqual(received?.expectedAppID, "com.example.app")
        XCTAssertEqual(received?.protectedResources, ["Assets/check.bin": pinHash]); XCTAssertEqual(scans, 1)
        XCTAssertEqual(result["checks"] as? [[String: String]], [
            ["code": "debugger_attached", "state": "detected"],
            ["code": "root_artifact", "state": "not_observed"],
            ["code": "hook_artifact", "state": "unavailable"],
            ["code": "app_identity_mismatch", "state": "not_observed"],
            ["code": "bundle_resource_mismatch", "state": "detected"]])
        XCTAssertEqual(result["riskSignals"] as? [String], ["debugger", "tamper", "local_checks_unavailable"])
        XCTAssertEqual(Set(result.keys), ["schema", "platform", "checks", "riskSignals"])
        XCTAssertFalse(text.contains("com.example.app")); XCTAssertFalse(text.contains(pinHash)); XCTAssertFalse(text.contains("Assets"))
        XCTAssertLessThanOrEqual(text.utf8.count, 4096)
    }

    func testOmittedAndEmptyCollectionsPreserveUnconfiguredStates() throws {
        for payload in ["{}", "{\"androidSignerSha256\":[],\"protectedResources\":{}}"] {
            let result = try success(makeBridge().invoke(operation: "scanLocalRisk", payload: payload))
            let checks = try XCTUnwrap(result["checks"] as? [[String: String]])
            XCTAssertEqual(checks.suffix(2).map { $0["state"] }, ["not_configured", "not_configured"])
        }
    }

    // A native throwing probe is unknown evidence, not a failed bridge or a negative observation.
    func testNativeProbeFailuresRemainUnavailableAndRedacted() throws {
        let bridge = makeBridge { LocalRiskScanner(probe: BridgeThrowingRiskProbe()).scan(configuration: $0) }
        let result = try success(bridge.invoke(operation: "scanLocalRisk", payload: json(["expectedAppId": "com.example.app", "protectedResources": ["file": pinHash]])))
        let checks = try XCTUnwrap(result["checks"] as? [[String: String]])
        XCTAssertEqual(checks.map { $0["state"] }, Array(repeating: "unavailable", count: 5))
        XCTAssertEqual(result["riskSignals"] as? [String], ["local_checks_unavailable"])
    }

    func testUnknownKeysAndWrongTypesRejectBeforeAnyScanKeyOrClock() throws {
        var scans = 0
        let bridge = makeBridge { config in scans += 1; return LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: config) }
        var invalid = ["", "[]", "null", "1", "{}x", "{\"expectedAppId\":\"com.example.app\",}"]
        for name in ["alias", "hardwareRequirement", "clock", "now", "observations", "expectedAppID", "extra"] {
            invalid.append(try json([name: "secret"]))
        }
        for value in [NSNull(), true, 1, [], [:]] as [Any] { invalid.append(try json(["expectedAppId": value])) }
        for value in [NSNull(), true, 1, "secret", [:]] as [Any] { invalid.append(try json(["androidSignerSha256": value])) }
        for value in [NSNull(), true, 1, "secret", []] as [Any] { invalid.append(try json(["protectedResources": value])) }
        for value in [NSNull(), true, 1, [], [:]] as [Any] { invalid.append(try json(["protectedResources": ["file": value]])) }
        for payload in invalid { assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: payload)) }
        XCTAssertEqual(scans, 0)
    }

    func testDuplicateDecodedKeysRejectAtAllObjectLevels() {
        var scans = 0
        let bridge = makeBridge { config in scans += 1; return LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: config) }
        for payload in [
            "{\"expectedAppId\":\"a\",\"expectedAppId\":\"b\"}",
            "{\"expectedAppId\":\"a\",\"\\u0065xpectedAppId\":\"b\"}",
            "{\"androidSignerSha256\":[],\"\\u0061ndroidSignerSha256\":[]}",
            "{\"protectedResources\":{},\"protectedResources\":{}}",
            "{\"protectedResources\":{\"file\":\"\(pinHash)\",\"\\u0066ile\":\"\(pinHash)\"}}"
        ] { assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: payload)) }
        XCTAssertEqual(scans, 0)
    }

    func testStringArraysRejectNestedNonstringTrailingAndOverEightValues() throws {
        var scans = 0
        let bridge = makeBridge { config in scans += 1; return LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: config) }
        for array in ["[null]", "[true]", "[1]", "[{}]", "[[]]", "[\"\(pinHash)\",]", "[", "[\"\\ud800\"]"] {
            assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: "{\"androidSignerSha256\":\(array)}"))
        }
        let nine = (0..<9).map { String(format: "%064x", $0) }
        assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: try json(["androidSignerSha256": nine])))
        XCTAssertEqual(scans, 0)
    }

    func testMalformedSignerPinsAndDuplicatesAreInvalidRatherThanUnsupported() throws {
        var scans = 0
        let bridge = makeBridge { config in scans += 1; return LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: config) }
        for pin in ["", String(repeating: "a", count: 63), String(repeating: "a", count: 65), String(repeating: "A", count: 64), String(repeating: "g", count: 64), String(repeating: "é", count: 64)] {
            assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: try json(["androidSignerSha256": [pin]])))
        }
        for pins in [[pinHash, pinHash], [pinHash, String(repeating: "A", count: 64)]] {
            assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: try json(["androidSignerSha256": pins])))
        }
        let escapedDuplicate = "{\"androidSignerSha256\":[\"\(pinHash)\",\"\\u0061\(pinHash.dropFirst())\"]}"
        assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: escapedDuplicate))
        XCTAssertEqual(scans, 0)
    }

    func testValidAndroidSignerPinsAreUnsupportedAfterAllConfigurationIsValidated() throws {
        var scans = 0
        let bridge = makeBridge { config in scans += 1; return LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: config) }
        for pins in [[pinHash], (0..<8).map { String(format: "%064x", $0) }] {
            assertError("APPGUARD_UNSUPPORTED", bridge.invoke(operation: "scanLocalRisk", payload: try json(["androidSignerSha256": pins])))
            for bad in [["expectedAppId": ""], ["protectedResources": ["../secret": pinHash]], ["protectedResources": ["file": "bad"]]] as [[String: Any]] {
                var config = bad; config["androidSignerSha256"] = pins
                assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: try json(config)))
            }
        }
        XCTAssertEqual(scans, 0)
    }

    func testIdentifiersResourcesAndTheirBoundsRejectBeforeScan() throws {
        var scans = 0
        let bridge = makeBridge { config in scans += 1; return LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: config) }
        for value in ["", "-a", "_a", ".a", "a b", "a/b", "a\n", "é", String(repeating: "a", count: 256)] {
            assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: try json(["expectedAppId": value])))
        }
        for path in ["", "/a", "a/", "a//b", ".", "..", "a/../b", "a/./b", "a\\b", "a b", "a%2fb", "é", String(repeating: "a", count: 129), String(repeating: "a", count: 128) + "/" + String(repeating: "b", count: 128)] {
            assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: try json(["protectedResources": [path: pinHash]])))
        }
        for pin in ["", String(repeating: "A", count: 64), String(repeating: "g", count: 64), String(repeating: "a", count: 63)] {
            assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: try json(["protectedResources": ["file": pin]])))
        }
        let nine = Dictionary(uniqueKeysWithValues: (0..<9).map { ("file\($0)", pinHash) })
        assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: try json(["protectedResources": nine])))
        XCTAssertEqual(scans, 0)
    }

    func testMaximumConfigurationAndEscapedASCIIReachTypedScannerWithoutCoercion() throws {
        var received: LocalRiskConfiguration?
        let bridge = makeBridge { config in received = config; return LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: config) }
        let path = String(repeating: "a", count: 128) + "/" + String(repeating: "b", count: 127)
        var resources = Dictionary(uniqueKeysWithValues: (0..<7).map { ("file\($0)", pinHash) }); resources[path] = pinHash
        let payload = try json(["expectedAppId": String(repeating: "a", count: 255), "protectedResources": resources])
        _ = try success(bridge.invoke(operation: "scanLocalRisk", payload: payload))
        XCTAssertEqual(received?.expectedAppID?.count, 255); XCTAssertEqual(received?.protectedResources, resources)
        _ = try success(bridge.invoke(operation: "scanLocalRisk", payload: "{\"expectedAppId\":\"com.\\u0065xample.app\",\"protectedResources\":{\"dir\\/file\":\"\(pinHash)\"}}"))
        XCTAssertEqual(received?.expectedAppID, "com.example.app"); XCTAssertEqual(received?.protectedResources, ["dir/file": pinHash])
    }

    func testExact8192ByteInputLimitAndUTF8RatherThanCharacterCounting() throws {
        var scans = 0
        let bridge = makeBridge { config in scans += 1; return LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: config) }
        _ = try success(bridge.invoke(operation: "scanLocalRisk", payload: "{}" + String(repeating: " ", count: 8190)))
        assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: "{}" + String(repeating: " ", count: 8191)))
        let multibyte = "{\"expectedAppId\":\"" + String(repeating: "é", count: 4090) + "\"}"
        XCTAssertLessThan(multibyte.count, 8192); XCTAssertGreaterThan(multibyte.utf8.count, 8192)
        assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: multibyte))
        XCTAssertEqual(scans, 1)
    }

    func testScanFailureEnvelopesAreFixedAndOldOperationsStillRejectArraysAndExtraFields() throws {
        let bridge = makeBridge()
        for operation in ["publicKey", "prepare", "enrollmentProof"] {
            for payload in ["{\"alias\":[],\"hardwareRequirement\":\"any\"}", "{\"alias\":\"x\",\"hardwareRequirement\":\"any\",\"androidSignerSha256\":[]}"] {
                assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: operation, payload: payload))
            }
        }
        assertError("APPGUARD_UNSUPPORTED", bridge.invoke(operation: "ScanLocalRisk", payload: "{}"))
        assertError("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "scanLocalRisk", payload: "{\"expectedAppId\":\"secret\nraw\"}"))
    }

    // Even a future scanner regression must not bypass the bridge's output budget.
    func testOversizedTypedScannerOutputReturnsBoundedFixedFailure() throws {
        let oversized = LocalRiskReport(checks: Array(repeating: LocalRiskCheck(code: .debuggerAttached, state: .unavailable), count: 100))
        XCTAssertGreaterThan(try JSONEncoder().encode(oversized).count, 4096)
        let bridge = makeBridge { _ in oversized }
        assertError("APPGUARD_OPERATION_FAILED", bridge.invoke(operation: "scanLocalRisk", payload: "{}"))
    }

    private func makeBridge(scanner: @escaping (LocalRiskConfiguration) -> LocalRiskReport = { LocalRiskScanner(probe: BridgeRiskProbe()).scan(configuration: $0) }) -> NativeBridge {
        NativeBridge(keyProvider: { _, _ in XCTFail("scan must not load a key"); throw TestFailure.secret }, clock: { XCTFail("scan must not call a clock"); return 0 }, localRiskScanner: scanner)
    }
    private func json(_ value: [String: Any]) throws -> String { String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), as: UTF8.self) }
    private func success(_ text: String, file: StaticString = #filePath, line: UInt = #line) throws -> [String: Any] {
        let out = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any], file: file, line: line)
        XCTAssertEqual(Set(out.keys), ["ok", "result"], text, file: file, line: line)
        XCTAssertEqual(out["ok"] as? Bool, true, text, file: file, line: line)
        let result = try XCTUnwrap(out["result"] as? [String: Any], file: file, line: line)
        let checks = try XCTUnwrap(result["checks"] as? [[String: String]], file: file, line: line)
        XCTAssertTrue(checks.allSatisfy { Set($0.keys) == ["code", "state"] }, file: file, line: line)
        return result
    }
    private func assertError(_ code: String, _ text: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(text, "{\"ok\":false,\"error\":{\"code\":\"\(code)\"}}", file: file, line: line)
        XCTAssertLessThanOrEqual(text.utf8.count, 4096, file: file, line: line)
    }
    private enum TestFailure: Error { case secret }
}

private struct BridgeRiskProbe: LocalRiskProbe {
    func debuggerAttached() throws -> LocalRiskObservation { .present }
    func rootArtifacts() throws -> [LocalRiskObservation] { [.absent] }
    func hookArtifacts() throws -> [LocalRiskObservation] { [.unavailable] }
    func appIdentifier() throws -> String? { "com.example.app" }
    func resourceObservations(_ pins: [String: String]) throws -> [LocalRiskObservation] { [.present] }
}
private struct BridgeThrowingRiskProbe: LocalRiskProbe {
    private func fail<T>() throws -> T { throw NSError(domain: "secret /private/raw", code: 4) }
    func debuggerAttached() throws -> LocalRiskObservation { try fail() }
    func rootArtifacts() throws -> [LocalRiskObservation] { try fail() }
    func hookArtifacts() throws -> [LocalRiskObservation] { try fail() }
    func appIdentifier() throws -> String? { try fail() }
    func resourceObservations(_ pins: [String: String]) throws -> [LocalRiskObservation] { try fail() }
}
