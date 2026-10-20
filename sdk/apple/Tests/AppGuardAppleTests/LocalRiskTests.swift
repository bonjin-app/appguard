import XCTest
import Foundation
import Darwin
@testable import AppGuardApple

final class LocalRiskTests: XCTestCase {
    private let emptyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    private let abcHash = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

    // A missing state, reordered check, or accidental clean bool breaks the wire contract.
    func testWireShapeAndStableCheckOrder() throws {
        let report = LocalRiskScanner(probe: FixtureRiskProbe()).scan(configuration: try LocalRiskConfiguration())
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: JSONEncoder().encode(report)) as? [String: Any])
        XCTAssertEqual(Set(object.keys), ["schema", "platform", "checks", "riskSignals"])
        XCTAssertEqual(object["schema"] as? String, "appguard-local-risk-v0")
        XCTAssertEqual(object["platform"] as? String, "ios")
        let checks = try XCTUnwrap(object["checks"] as? [[String: String]])
        XCTAssertEqual(checks, [
            ["code": "debugger_attached", "state": "not_observed"],
            ["code": "root_artifact", "state": "not_observed"],
            ["code": "hook_artifact", "state": "not_observed"],
            ["code": "app_identity_mismatch", "state": "not_configured"],
            ["code": "bundle_resource_mismatch", "state": "not_configured"]
        ])
        XCTAssertEqual(object["riskSignals"] as? [String], [])
        XCTAssertEqual(try JSONDecoder().decode(LocalRiskReport.self, from: JSONEncoder().encode(report)), report)
    }

    // Replacing precedence with first/last observation loses positive or unknown evidence.
    func testDetectedWinsUnavailableAndUnavailableWinsAbsence() throws {
        let probe = FixtureRiskProbe(root: [.unavailable, .present, .absent], hook: [.absent, .unavailable])
        let report = LocalRiskScanner(probe: probe).scan(configuration: try LocalRiskConfiguration())
        XCTAssertEqual(report.checks.map(\.state), [.notObserved, .detected, .unavailable, .notConfigured, .notConfigured])
        XCTAssertEqual(report.riskSignals, [.root, .localChecksUnavailable])
    }

    func testSignalsAreOrderedAndTamperIsDeduplicated() throws {
        let probe = FixtureRiskProbe(debugger: .present, root: [.present], hook: [.present], appID: "wrong.app", resources: [.present])
        let config = try LocalRiskConfiguration(expectedAppID: "expected.app", protectedResources: ["file": emptyHash])
        let report = LocalRiskScanner(probe: probe).scan(configuration: config)
        XCTAssertEqual(report.checks.map(\.state), Array(repeating: .detected, count: 5))
        XCTAssertEqual(report.riskSignals, [.debugger, .root, .hook, .tamper])
    }

    func testEveryProbeFailureBecomesUnavailableWithoutLeakingError() throws {
        let config = try LocalRiskConfiguration(expectedAppID: "expected.app", protectedResources: ["file": emptyHash])
        let report = LocalRiskScanner(probe: ThrowingRiskProbe()).scan(configuration: config)
        XCTAssertEqual(report.checks.map(\.state), Array(repeating: .unavailable, count: 5))
        XCTAssertEqual(report.riskSignals, [.localChecksUnavailable])
        XCTAssertFalse(String(describing: report).contains("secret"))
        XCTAssertFalse(String(reflecting: report).contains("secret"))
    }

    func testEmptyObservationSetsRemainUnavailable() throws {
        let probe = FixtureRiskProbe(root: [], hook: [], resources: [])
        let config = try LocalRiskConfiguration(protectedResources: ["file": emptyHash])
        XCTAssertEqual(LocalRiskScanner(probe: probe).scan(configuration: config).checks.map(\.state),
                       [.notObserved, .unavailable, .unavailable, .notConfigured, .unavailable])
    }

    func testUnconfiguredChecksDoNotInvokeIdentityOrResources() throws {
        let probe = UnconfiguredRiskProbe()
        let report = LocalRiskScanner(probe: probe).scan(configuration: try LocalRiskConfiguration())
        XCTAssertEqual(Array(report.checks.suffix(2)).map(\.state), [.notConfigured, .notConfigured])
        XCTAssertEqual(probe.configuredCalls, 0)
    }

    func testIdentityMatchMismatchAndMissingHaveDistinctStates() throws {
        let config = try LocalRiskConfiguration(expectedAppID: "com.example.app")
        for (identifier, expected) in [("com.example.app", LocalRiskState.notObserved), ("com.other.app", .detected), (nil, .unavailable)] {
            let report = LocalRiskScanner(probe: FixtureRiskProbe(appID: identifier)).scan(configuration: config)
            XCTAssertEqual(report.checks[3].state, expected)
        }
        let oversized = LocalRiskScanner(probe: FixtureRiskProbe(appID: String(repeating: "a", count: 256))).scan(configuration: config)
        XCTAssertEqual(oversized.checks[3].state, .unavailable)
    }

    // Swift String equality normalizes Unicode; an observed non-ASCII ID must not match an ASCII pin.
    func testIdentityComparisonRequiresExactASCIIBytes() throws {
        let config = try LocalRiskConfiguration(expectedAppID: "com.example.K")
        let report = LocalRiskScanner(probe: FixtureRiskProbe(appID: "com.example.\u{212A}")).scan(configuration: config)
        XCTAssertEqual(report.checks[3].state, .detected)
        XCTAssertEqual(report.riskSignals, [.tamper])
    }

    // Invalid config must reject before a scanner can receive it; fixed errors hide all raw input.
    func testInvalidIdentifiersHaveFixedRedactedErrors() throws {
        for identifier in ["", "-a", "_a", ".a", "a b", "a/b", "a\n", "é", String(repeating: "a", count: 256)] {
            assertInvalid { _ = try LocalRiskConfiguration(expectedAppID: identifier) }
        }
        _ = try LocalRiskConfiguration(expectedAppID: String(repeating: "a", count: 255))
        _ = try LocalRiskConfiguration(expectedAppID: "1.com_A-b")
    }

    func testResourcePathAndPinValidationRejectsTraversalAndUnboundedInputs() throws {
        for path in ["", "/a", "a/", "a//b", ".", "..", "a/../b", "a/./b", "a\\b", "a b", "a%2fb", "é", "a\0b",
                     String(repeating: "a", count: 129), "a/" + String(repeating: "b", count: 128) + "/" + String(repeating: "c", count: 127)] {
            assertInvalid { _ = try LocalRiskConfiguration(protectedResources: [path: emptyHash]) }
        }
        for hash in ["", String(repeating: "a", count: 63), String(repeating: "a", count: 65), String(repeating: "A", count: 64), String(repeating: "g", count: 64)] {
            assertInvalid { _ = try LocalRiskConfiguration(protectedResources: ["file": hash]) }
        }
        let tooMany = Dictionary(uniqueKeysWithValues: (0..<9).map { ("f\($0)", emptyHash) })
        assertInvalid { _ = try LocalRiskConfiguration(protectedResources: tooMany) }
        _ = try LocalRiskConfiguration(protectedResources: [String(repeating: "a", count: 128) + "/" + String(repeating: "b", count: 127): emptyHash])
        _ = try LocalRiskConfiguration(protectedResources: ["_a/-b.c": emptyHash])
    }

    func testConfigurationAndReportDescriptionsRedactInputs() throws {
        let config = try LocalRiskConfiguration(expectedAppID: "secret.identifier", protectedResources: ["secret.resource": abcHash])
        let report = LocalRiskScanner(probe: FixtureRiskProbe(appID: "another.secret", resources: [.present])).scan(configuration: config)
        for text in [String(describing: config), String(reflecting: config), String(describing: report), String(reflecting: report),
                     String(decoding: try JSONEncoder().encode(report), as: UTF8.self)] {
            for secret in ["secret.identifier", "secret.resource", "another.secret", abcHash] { XCTAssertFalse(text.contains(secret)) }
        }
    }

    func testValueSemanticsPreserveConfigurationAndReport() throws {
        var resources = ["file": abcHash]
        let config = try LocalRiskConfiguration(protectedResources: resources)
        resources["file"] = emptyHash
        XCTAssertEqual(config.protectedResources["file"], abcHash)
        let report = LocalRiskScanner(probe: FixtureRiskProbe()).scan(configuration: config)
        var checks = report.checks
        checks.removeAll()
        var signals = report.riskSignals
        signals.removeAll()
        XCTAssertEqual(report.checks.count, 5)
        XCTAssertEqual(report.checks.last?.state, .notObserved)
    }

    func testMalformedReportsRejectWithFixedError() throws {
        let report = LocalRiskScanner(probe: FixtureRiskProbe()).scan(configuration: try LocalRiskConfiguration())
        let encoded = String(decoding: try JSONEncoder().encode(report), as: UTF8.self)
        for malformed in [encoded.replacingOccurrences(of: "appguard-local-risk-v0", with: "secret-schema"),
                          encoded.replacingOccurrences(of: "\"ios\"", with: "\"secret-platform\""),
                          encoded.replacingOccurrences(of: "not_observed", with: "secret-state"),
                          encoded.replacingOccurrences(of: "debugger_attached", with: "secret-code"),
                          encoded.replacingOccurrences(of: "\"riskSignals\":[]", with: "\"riskSignals\":[\"tamper\"]"),
                          "{}"] {
            XCTAssertThrowsError(try JSONDecoder().decode(LocalRiskReport.self, from: Data(malformed.utf8))) { error in
                XCTAssertEqual(error as? LocalRiskError, .invalidReport)
                XCTAssertFalse(String(reflecting: error).contains("secret"))
            }
        }
    }

    // Decoding a public nested value must not expose hostile raw strings through Foundation's enum error.
    func testMalformedNestedWireValuesAlsoHaveFixedRedactedErrors() {
        let secret = Data("\"secret-resource-path\"".utf8)
        for action in [
            { _ = try JSONDecoder().decode(LocalRiskState.self, from: secret) },
            { _ = try JSONDecoder().decode(LocalRiskCode.self, from: secret) },
            { _ = try JSONDecoder().decode(LocalRiskSignal.self, from: secret) },
            { _ = try JSONDecoder().decode(LocalRiskCheck.self, from: Data("{\"code\":\"debugger_attached\",\"state\":\"secret-resource-path\"}".utf8)) }
        ] {
            XCTAssertThrowsError(try action()) { error in
                XCTAssertEqual(error as? LocalRiskError, .invalidReport)
                XCTAssertFalse(String(reflecting: error).contains("secret-resource-path"))
            }
        }
    }

    func testNativeHostAndSimulatorNeverDiagnoseHostJailbreakOrHook() throws {
        #if !os(iOS) || targetEnvironment(simulator)
        let report = LocalRiskScanner().scan(configuration: try LocalRiskConfiguration())
        XCTAssertEqual(report.checks[1].state, .unavailable)
        XCTAssertEqual(report.checks[2].state, .unavailable)
        XCTAssertEqual(report.riskSignals, [.localChecksUnavailable])
        #endif
        #if !os(iOS) || !DEBUG
        XCTAssertEqual(LocalRiskScanner().scan(configuration: try LocalRiskConfiguration()).checks[0].state, .unavailable)
        #endif
    }

    func testDeviceArtifactSubprobesPreserveUnknownAndPositivePrecedence() {
        let device = LocalRiskDeviceProbes(artifact: { path in path.hasSuffix("Cydia.app") ? .present : .unavailable },
                                           symbol: { _ in .absent }, environment: { _ in .unavailable })
        XCTAssertEqual(LocalRiskScanner.reduce(device.rootArtifacts()), .detected)
        XCTAssertEqual(LocalRiskScanner.reduce(device.hookArtifacts()), .unavailable)
        let hooked = LocalRiskDeviceProbes(artifact: { _ in .absent }, symbol: { _ in .unavailable }, environment: { _ in .present })
        XCTAssertEqual(LocalRiskScanner.reduce(hooked.rootArtifacts()), .notObserved)
        XCTAssertEqual(LocalRiskScanner.reduce(hooked.hookArtifacts()), .detected)
    }

    func testExistenceFailureClassificationDistinguishesAbsentAndDenied() {
        XCTAssertEqual(LocalRiskNativeProbe.fileObservation(result: -1, error: ENOENT), .absent)
        XCTAssertEqual(LocalRiskNativeProbe.fileObservation(result: -1, error: ENOTDIR), .absent)
        for error in [EACCES, EPERM, EIO, ELOOP] {
            XCTAssertEqual(LocalRiskNativeProbe.fileObservation(result: -1, error: error), .unavailable)
        }
        XCTAssertEqual(LocalRiskNativeProbe.fileObservation(result: 0, error: EACCES), .present)
    }

    func testEnvironmentObservationIsBoundedAndDoesNotExposeValues() {
        XCTAssertEqual(LocalRiskNativeProbe.environmentObservation(nil), .absent)
        "".withCString { XCTAssertEqual(LocalRiskNativeProbe.environmentObservation($0), .absent) }
        "injected-secret".withCString { XCTAssertEqual(LocalRiskNativeProbe.environmentObservation($0), .present) }
        String(repeating: "x", count: 4096).withCString { XCTAssertEqual(LocalRiskNativeProbe.environmentObservation($0), .present) }
        String(repeating: "x", count: 4097).withCString { XCTAssertEqual(LocalRiskNativeProbe.environmentObservation($0), .unavailable) }
    }

    func testRealResourceExactBytesEmptyAndMissing() throws {
        try withFixtureBundle { bundle in
            try Data("abc".utf8).write(to: bundle.bundleURL.appendingPathComponent("binary"))
            try Data().write(to: bundle.bundleURL.appendingPathComponent("empty"))
            XCTAssertEqual(try resourceState(bundle, ["binary": abcHash, "empty": emptyHash]), .notObserved)
            XCTAssertEqual(try resourceState(bundle, ["binary": emptyHash]), .detected)
            XCTAssertEqual(try resourceState(bundle, ["missing": emptyHash]), .detected)
        }
    }

    func testRealResourceBinaryHashUsesAllBytesWithoutTextNormalization() throws {
        try withFixtureBundle { bundle in
            // printf '\000\377\001\015\012' | shasum -a 256, independently checked fixture digest.
            try Data([0, 255, 1, 13, 10]).write(to: bundle.bundleURL.appendingPathComponent("binary"))
            XCTAssertEqual(try resourceState(bundle, ["binary": "78b616c5b9b6b3c72b82dfeb33a404b9705c640c2277e8ca150b6d70bd9449d4"]), .notObserved)
        }
    }

    func testRealResourceLimitAcceptsExactlyOneMiBAndRejectsLarger() throws {
        try withFixtureBundle { bundle in
            try Data(repeating: 0, count: 1_048_576).write(to: bundle.bundleURL.appendingPathComponent("limit"))
            try Data(repeating: 0, count: 1_048_577).write(to: bundle.bundleURL.appendingPathComponent("large"))
            XCTAssertEqual(try resourceState(bundle, ["limit": "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"]), .notObserved)
            XCTAssertEqual(try resourceState(bundle, ["large": emptyHash]), .unavailable)
        }
    }

    // Retrying native errors without a bound can hang a synchronous scan or erase an unavailable observation.
    func testInterruptedResourceReadIsUnavailableWithoutRetry() throws {
        try withFixtureBundle { bundle in
            try Data().write(to: bundle.bundleURL.appendingPathComponent("empty"))
            var calls = 0
            let probe = LocalRiskNativeProbe(bundle: bundle, readBytes: { _, _, _ in
                calls += 1
                if calls <= 3 { errno = EINTR; return -1 }
                return 0
            })
            let report = LocalRiskScanner(probe: probe).scan(configuration: try LocalRiskConfiguration(protectedResources: ["empty": emptyHash]))
            XCTAssertEqual(report.checks[4].state, .unavailable)
            XCTAssertEqual(calls, 1)
        }
    }

    func testRealResourcePermissionFailureIsUnknownAndRestoredReadMatches() throws {
        try withFixtureBundle { bundle in
            let path = bundle.bundleURL.appendingPathComponent("denied")
            try Data("abc".utf8).write(to: path)
            XCTAssertEqual(chmod(path.path, 0), 0)
            defer { _ = chmod(path.path, 0o600) }
            XCTAssertEqual(try resourceState(bundle, ["denied": abcHash]), .unavailable)
            XCTAssertEqual(chmod(path.path, 0o600), 0)
            XCTAssertEqual(try resourceState(bundle, ["denied": abcHash]), .notObserved)
        }
    }

    func testNonregularResourceIsUnknownWithoutBlockingOnFIFO() throws {
        try withFixtureBundle { bundle in
            let path = bundle.bundleURL.appendingPathComponent("fifo")
            XCTAssertEqual(mkfifo(path.path, 0o600), 0)
            XCTAssertEqual(try resourceState(bundle, ["fifo": emptyHash]), .unavailable)
        }
    }

    func testResourceStreamingNeverReadsPastOneMiB() throws {
        try withFixtureBundle { bundle in
            try Data(repeating: 0, count: 1_048_576).write(to: bundle.bundleURL.appendingPathComponent("limit"))
            var total = 0
            var maximumRequest = 0
            let probe = LocalRiskNativeProbe(bundle: bundle, readBytes: { descriptor, buffer, requested in
                maximumRequest = max(maximumRequest, requested)
                let count = Darwin.read(descriptor, buffer, requested)
                if count > 0 { total += count }
                XCTAssertLessThanOrEqual(total, 1_048_576)
                return count
            })
            let pins = ["limit": "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"]
            XCTAssertEqual(LocalRiskScanner(probe: probe).scan(configuration: try LocalRiskConfiguration(protectedResources: pins)).checks[4].state, .notObserved)
            XCTAssertEqual(total, 1_048_576)
            XCTAssertLessThanOrEqual(maximumRequest, 16_384)
        }
    }

    func testEightResourceAggregateLimitRemainsUsable() throws {
        try withFixtureBundle { bundle in
            var pins: [String: String] = [:]
            for index in 0..<8 {
                let path = "resource\(index)"
                try Data(repeating: 0, count: 1_048_576).write(to: bundle.bundleURL.appendingPathComponent(path))
                pins[path] = "30e14955ebf1352266dc2ff8067e68104607e750abb9d3b36582b8af909fcb58"
            }
            XCTAssertEqual(try resourceState(bundle, pins), .notObserved)
        }
    }

    func testResourceMismatchWinsUnreadableSibling() throws {
        try withFixtureBundle { bundle in
            try FileManager.default.createDirectory(at: bundle.bundleURL.appendingPathComponent("directory"), withIntermediateDirectories: true)
            XCTAssertEqual(try resourceState(bundle, ["directory": emptyHash]), .unavailable)
            XCTAssertEqual(try resourceState(bundle, ["directory": emptyHash, "missing": emptyHash]), .detected)
        }
    }

    func testRealResourceSymlinksStayWithinBundle() throws {
        try withFixtureBundle { bundle in
            let root = bundle.bundleURL
            try Data("abc".utf8).write(to: root.appendingPathComponent("real"))
            try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("inside").path, withDestinationPath: "real")
            XCTAssertEqual(try resourceState(bundle, ["inside": abcHash]), .notObserved)
            let outside = root.deletingLastPathComponent().appendingPathComponent("outside")
            try Data("abc".utf8).write(to: outside)
            try FileManager.default.createSymbolicLink(atPath: root.appendingPathComponent("escape").path, withDestinationPath: outside.path)
            XCTAssertEqual(try resourceState(bundle, ["escape": abcHash]), .unavailable)
        }
    }

    func testSymlinkSiblingPrefixAndDirectoryEscapeAreRejected() throws {
        try withFixtureBundle { bundle in
            let sibling = URL(fileURLWithPath: bundle.bundleURL.path + "-other")
            try FileManager.default.createDirectory(at: sibling, withIntermediateDirectories: true)
            try Data("abc".utf8).write(to: sibling.appendingPathComponent("file"))
            try FileManager.default.createSymbolicLink(atPath: bundle.bundleURL.appendingPathComponent("directory").path, withDestinationPath: sibling.path)
            XCTAssertEqual(try resourceState(bundle, ["directory/file": abcHash]), .unavailable)
        }
    }

    func testSymlinkLoopReadFailureIsUnavailable() throws {
        try withFixtureBundle { bundle in
            try FileManager.default.createSymbolicLink(atPath: bundle.bundleURL.appendingPathComponent("loop").path, withDestinationPath: "loop")
            XCTAssertEqual(try resourceState(bundle, ["loop": emptyHash]), .unavailable)
        }
    }

    func testTemporaryBundleIdentityUsesActualBundleIdentifier() throws {
        try withFixtureBundle { bundle in
            let scanner = LocalRiskScanner(probe: LocalRiskNativeProbe(bundle: bundle))
            XCTAssertEqual(scanner.scan(configuration: try LocalRiskConfiguration(expectedAppID: "com.example.fixture")).checks[3].state, .notObserved)
            XCTAssertEqual(scanner.scan(configuration: try LocalRiskConfiguration(expectedAppID: "com.other.app")).checks[3].state, .detected)
        }
    }

    private func resourceState(_ bundle: Bundle, _ pins: [String: String]) throws -> LocalRiskState {
        LocalRiskScanner(probe: LocalRiskNativeProbe(bundle: bundle)).scan(configuration: try LocalRiskConfiguration(protectedResources: pins)).checks[4].state
    }

    private func assertInvalid(_ action: () throws -> Void, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try action(), file: file, line: line) { error in
            XCTAssertEqual(error as? LocalRiskError, .invalidConfiguration, file: file, line: line)
            XCTAssertEqual(String(describing: error), "invalid-configuration", file: file, line: line)
            XCTAssertEqual((error as NSError).localizedDescription, "invalid-configuration", file: file, line: line)
        }
    }

    private func withFixtureBundle(_ body: (Bundle) throws -> Void) throws {
        let temporary = FileManager.default.temporaryDirectory.appendingPathComponent("appguard-local-risk-" + UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: temporary) }
        let root = temporary.appendingPathComponent("Fixture.bundle")
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        let info: [String: String] = ["CFBundleIdentifier": "com.example.fixture", "CFBundlePackageType": "BNDL"]
        try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(to: root.appendingPathComponent("Info.plist"))
        try body(XCTUnwrap(Bundle(url: root)))
    }
}

private final class FixtureRiskProbe: LocalRiskProbe {
    let debugger: LocalRiskObservation
    let root: [LocalRiskObservation]
    let hook: [LocalRiskObservation]
    let appID: String?
    let resources: [LocalRiskObservation]
    init(debugger: LocalRiskObservation = .absent, root: [LocalRiskObservation] = [.absent], hook: [LocalRiskObservation] = [.absent],
         appID: String? = nil, resources: [LocalRiskObservation] = [.absent]) {
        self.debugger = debugger; self.root = root; self.hook = hook; self.appID = appID; self.resources = resources
    }
    func debuggerAttached() throws -> LocalRiskObservation { debugger }
    func rootArtifacts() throws -> [LocalRiskObservation] { root }
    func hookArtifacts() throws -> [LocalRiskObservation] { hook }
    func appIdentifier() throws -> String? { appID }
    func resourceObservations(_ pins: [String: String]) throws -> [LocalRiskObservation] { resources }
}

private final class ThrowingRiskProbe: LocalRiskProbe {
    private let error = NSError(domain: "secret-path-or-probe-error", code: 1)
    func debuggerAttached() throws -> LocalRiskObservation { throw error }
    func rootArtifacts() throws -> [LocalRiskObservation] { throw error }
    func hookArtifacts() throws -> [LocalRiskObservation] { throw error }
    func appIdentifier() throws -> String? { throw error }
    func resourceObservations(_ pins: [String: String]) throws -> [LocalRiskObservation] { throw error }
}

private final class UnconfiguredRiskProbe: LocalRiskProbe {
    var configuredCalls = 0
    func debuggerAttached() throws -> LocalRiskObservation { .absent }
    func rootArtifacts() throws -> [LocalRiskObservation] { [.absent] }
    func hookArtifacts() throws -> [LocalRiskObservation] { [.absent] }
    func appIdentifier() throws -> String? { configuredCalls += 1; throw NSError(domain: "unused", code: 1) }
    func resourceObservations(_ pins: [String: String]) throws -> [LocalRiskObservation] { configuredCalls += 1; throw NSError(domain: "unused", code: 1) }
}
