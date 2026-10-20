import Foundation

/// Fixed errors never retain configuration values or native failure details.
public enum LocalRiskError: Error, Equatable, CustomStringConvertible, CustomDebugStringConvertible, LocalizedError {
    case invalidConfiguration, invalidReport
    public var description: String { self == .invalidConfiguration ? "invalid-configuration" : "invalid-local-risk-report" }
    public var debugDescription: String { description }
    public var errorDescription: String? { description }
}

public enum LocalRiskState: String, Codable, Sendable {
    case detected, notObserved = "not_observed", unavailable, notConfigured = "not_configured"
    public init(from decoder: Decoder) throws { self = try decodeRiskValue(decoder, as: Self.self) }
}

public enum LocalRiskCode: String, Codable, CaseIterable, Sendable {
    case debuggerAttached = "debugger_attached", rootArtifact = "root_artifact", hookArtifact = "hook_artifact"
    case appIdentityMismatch = "app_identity_mismatch", bundleResourceMismatch = "bundle_resource_mismatch"
    public init(from decoder: Decoder) throws { self = try decodeRiskValue(decoder, as: Self.self) }
}

public enum LocalRiskSignal: String, Codable, CaseIterable, Sendable {
    case debugger, root, hook, tamper, localChecksUnavailable = "local_checks_unavailable"
    public init(from decoder: Decoder) throws { self = try decodeRiskValue(decoder, as: Self.self) }
}

private func decodeRiskValue<T: RawRepresentable>(_ decoder: Decoder, as type: T.Type) throws -> T where T.RawValue == String {
    do {
        let raw = try decoder.singleValueContainer().decode(String.self)
        guard let value = T(rawValue: raw) else { throw LocalRiskError.invalidReport }
        return value
    } catch { throw LocalRiskError.invalidReport }
}

public struct LocalRiskCheck: Codable, Equatable, Sendable {
    public let code: LocalRiskCode
    public let state: LocalRiskState
}

extension LocalRiskCheck {
    private enum CodingKeys: String, CodingKey { case code, state }
    public init(from decoder: Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            self.init(code: try container.decode(LocalRiskCode.self, forKey: .code), state: try container.decode(LocalRiskState.self, forKey: .state))
        } catch { throw LocalRiskError.invalidReport }
    }
}

/// Optional, untrusted hints. Empty signals never prove device or application integrity.
public struct LocalRiskReport: Codable, Equatable, Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    public let schema: String
    public let platform: String
    public let checks: [LocalRiskCheck]
    public let riskSignals: [LocalRiskSignal]

    init(checks: [LocalRiskCheck]) {
        schema = "appguard-local-risk-v0"; platform = "ios"
        self.checks = checks; riskSignals = Self.signals(checks)
    }

    private enum CodingKeys: String, CodingKey { case schema, platform, checks, riskSignals }
    public init(from decoder: Decoder) throws {
        do {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            let schema = try container.decode(String.self, forKey: .schema)
            let platform = try container.decode(String.self, forKey: .platform)
            let checks = try container.decode([LocalRiskCheck].self, forKey: .checks)
            let signals = try container.decode([LocalRiskSignal].self, forKey: .riskSignals)
            guard schema == "appguard-local-risk-v0", platform == "ios",
                  checks.map(\.code) == LocalRiskCode.allCases, Self.signals(checks) == signals,
                  checks.prefix(3).allSatisfy({ $0.state != .notConfigured }) else { throw LocalRiskError.invalidReport }
            self.init(checks: checks)
        } catch { throw LocalRiskError.invalidReport }
    }

    static func signals(_ checks: [LocalRiskCheck]) -> [LocalRiskSignal] {
        var found = Set<LocalRiskSignal>()
        for check in checks {
            if check.state == .unavailable { found.insert(.localChecksUnavailable) }
            guard check.state == .detected else { continue }
            switch check.code {
            case .debuggerAttached: found.insert(.debugger)
            case .rootArtifact: found.insert(.root)
            case .hookArtifact: found.insert(.hook)
            case .appIdentityMismatch, .bundleResourceMismatch: found.insert(.tamper)
            }
        }
        return LocalRiskSignal.allCases.filter { found.contains($0) }
    }

    public var description: String { "LocalRiskReport(\(schema), \(platform), checks: \(checks), riskSignals: \(riskSignals))" }
    public var debugDescription: String { description }
}

/// Pins must describe the exact deployed, untransformed app-owned resource bytes.
/// Values are intentionally excluded from descriptions and scan reports.
public struct LocalRiskConfiguration: Sendable, CustomStringConvertible, CustomDebugStringConvertible {
    let expectedAppID: String?
    let protectedResources: [String: String]

    public init(expectedAppID: String? = nil, protectedResources: [String: String] = [:]) throws {
        guard expectedAppID.map(Self.validIdentifier) ?? true, protectedResources.count <= 8,
              protectedResources.allSatisfy({ Self.validPath($0.key) && Self.validHash($0.value) }) else {
            throw LocalRiskError.invalidConfiguration
        }
        self.expectedAppID = expectedAppID; self.protectedResources = protectedResources
    }

    private static func alphanumeric(_ byte: UInt8) -> Bool { (48...57).contains(byte) || (65...90).contains(byte) || (97...122).contains(byte) }
    private static func identifierTail(_ byte: UInt8) -> Bool { alphanumeric(byte) || byte == 46 || byte == 95 || byte == 45 }
    private static func validIdentifier(_ value: String) -> Bool {
        let bytes = value.utf8
        return (1...255).contains(bytes.count) && bytes.first.map(alphanumeric) == true && bytes.allSatisfy(identifierTail)
    }
    private static func validHash(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    private static func validPath(_ path: String) -> Bool {
        guard (1...256).contains(path.utf8.count) else { return false }
        return path.utf8.split(separator: 47, omittingEmptySubsequences: false).allSatisfy { component in
            (1...128).contains(component.count) && component.first.map({ alphanumeric($0) || $0 == 95 || $0 == 45 }) == true && component.allSatisfy(identifierTail)
        }
    }
    public var description: String { "LocalRiskConfiguration(redacted)" }
    public var debugDescription: String { description }
}

enum LocalRiskObservation { case present, absent, unavailable }

// Internal OS boundary only. Consumer-supplied observations are never represented as genuine native scans.
protocol LocalRiskProbe {
    func debuggerAttached() throws -> LocalRiskObservation
    func rootArtifacts() throws -> [LocalRiskObservation]
    func hookArtifacts() throws -> [LocalRiskObservation]
    func appIdentifier() throws -> String?
    func resourceObservations(_ pins: [String: String]) throws -> [LocalRiskObservation]
}

/// A synchronous, read-only scan. Run off the UI thread; no scan changes authorization or attestation.
public struct LocalRiskScanner {
    private let probe: any LocalRiskProbe
    public init() { probe = LocalRiskNativeProbe() }
    init(probe: any LocalRiskProbe) { self.probe = probe }

    public func scan(configuration: LocalRiskConfiguration) -> LocalRiskReport {
        var checks = [LocalRiskCheck(code: .debuggerAttached, state: safely { Self.reduce([try probe.debuggerAttached()]) }),
                      LocalRiskCheck(code: .rootArtifact, state: safely { Self.reduce(try probe.rootArtifacts()) }),
                      LocalRiskCheck(code: .hookArtifact, state: safely { Self.reduce(try probe.hookArtifacts()) })]
        let identity: LocalRiskState
        if let expected = configuration.expectedAppID {
            identity = safely {
                guard let actual = try probe.appIdentifier(), (1...255).contains(actual.utf8.count) else { return .unavailable }
                return actual.utf8.elementsEqual(expected.utf8) ? .notObserved : .detected
            }
        } else { identity = .notConfigured }
        checks.append(LocalRiskCheck(code: .appIdentityMismatch, state: identity))
        let resources = configuration.protectedResources.isEmpty ? .notConfigured : safely {
            Self.reduce(try probe.resourceObservations(configuration.protectedResources))
        }
        checks.append(LocalRiskCheck(code: .bundleResourceMismatch, state: resources))
        return LocalRiskReport(checks: checks)
    }

    private func safely(_ action: () throws -> LocalRiskState) -> LocalRiskState {
        do { return try action() } catch { return .unavailable }
    }
    static func reduce(_ observations: [LocalRiskObservation]) -> LocalRiskState {
        if observations.contains(.present) { return .detected }
        if observations.isEmpty || observations.contains(.unavailable) { return .unavailable }
        return .notObserved
    }
}
