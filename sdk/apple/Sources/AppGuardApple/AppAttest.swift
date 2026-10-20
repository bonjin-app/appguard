import Foundation
#if canImport(DeviceCheck)
import DeviceCheck
#endif

public enum AppAttestSupport { case supported, unsupported, unavailable }
public enum AppAttestEnvironment: String { case development, production }
public enum AppAttestOperation: String { case attestation, assertion }
public enum AppAttestError: Error, Equatable {
    case invalidConfiguration, invalidChallengeHash, invalidKeyIdentifier, unsupported, unavailable
    case serverUnavailable, invalidKey, providerFailure, malformedProviderResponse
}

/// Explicit Apple App ID (TeamID.BundleID) and the caller's provisioned entitlement environment.
/// These values label evidence; this library cannot verify the app's signing/entitlement configuration.
public struct AppAttestConfiguration {
    public let appID: String
    public let environment: AppAttestEnvironment
    public init(appID: String, environment: AppAttestEnvironment) throws {
        guard appID.utf8.count <= 266,
              RequestProfile.matches(appID, "[A-Z0-9]{10}\\.[A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*") else { throw AppAttestError.invalidConfiguration }
        self.appID = appID; self.environment = environment
    }
}

/// Opaque untrusted acquisition output. Only a separate server verifier can establish attestation trust.
/// The Apple-managed, nonexportable App Attest key is distinct from an InstallationKey request key.
public struct AppAttestEvidence {
    public let appID: String
    public let environment: AppAttestEnvironment
    public let keyID: String
    public let operation: AppAttestOperation
    public let challengeHash: Data
    public let opaqueObject: Data
}

@MainActor protocol AppAttestService {
    var support: AppAttestSupport { get }
    func generateKey() async throws -> String
    func attest(keyID: String, challengeHash: Data) async throws -> Data
    func assertion(keyID: String, challengeHash: Data) async throws -> Data
}

@MainActor public final class AppAttestClient {
    public var support: AppAttestSupport { service.support }
    private let service: any AppAttestService
    public let configuration: AppAttestConfiguration
    public convenience init(configuration: AppAttestConfiguration) {
        self.init(configuration: configuration, service: DeviceCheckAppAttestService())
    }
    init(configuration: AppAttestConfiguration, service: any AppAttestService) {
        self.configuration = configuration; self.service = service
    }
    private func requireSupport() throws {
        switch support { case .supported: return; case .unsupported: throw AppAttestError.unsupported; case .unavailable: throw AppAttestError.unavailable }
    }
    private func validateKeyID(_ keyID: String) throws {
        guard (1...512).contains(keyID.utf8.count), keyID.utf8.allSatisfy({ 33...126 ~= $0 }) else { throw AppAttestError.invalidKeyIdentifier }
    }
    /// Persist the returned opaque Apple key ID in application storage. No automatic key rotation occurs.
    public func generateKey() async throws -> String {
        try requireSupport()
        do {
            let keyID = try await service.generateKey()
            do { try validateKeyID(keyID) } catch { throw AppAttestError.malformedProviderResponse }
            return keyID
        } catch let error as AppAttestError { throw error }
        catch { throw AppAttestError.providerFailure }
    }
    /// Supply SHA-256 of server-defined, single-use enrollment challenge bytes (exactly 32 bytes).
    public func attest(keyID: String, challengeHash: Data) async throws -> AppAttestEvidence {
        try await acquire(keyID: keyID, challengeHash: challengeHash, operation: .attestation)
    }
    /// Supply SHA-256 of server-defined bytes binding its challenge and the intended request.
    public func assertion(keyID: String, challengeHash: Data) async throws -> AppAttestEvidence {
        try await acquire(keyID: keyID, challengeHash: challengeHash, operation: .assertion)
    }
    private func acquire(keyID: String, challengeHash: Data, operation: AppAttestOperation) async throws -> AppAttestEvidence {
        try validateKeyID(keyID)
        guard challengeHash.count == 32 else { throw AppAttestError.invalidChallengeHash }
        let hash = Data(Array(challengeHash))
        try requireSupport()
        do {
            let object: Data
            switch operation {
            case .attestation: object = try await service.attest(keyID: keyID, challengeHash: hash)
            case .assertion: object = try await service.assertion(keyID: keyID, challengeHash: hash)
            }
            guard !object.isEmpty else { throw AppAttestError.malformedProviderResponse }
            return AppAttestEvidence(appID: configuration.appID, environment: configuration.environment, keyID: keyID,
                operation: operation, challengeHash: hash, opaqueObject: Data(Array(object)))
        } catch let error as AppAttestError { throw error }
        catch { throw AppAttestError.providerFailure }
    }
}

@MainActor private struct DeviceCheckAppAttestService: AppAttestService {
    var support: AppAttestSupport {
        #if canImport(DeviceCheck)
        return DCAppAttestService.shared.isSupported ? .supported : .unsupported
        #else
        return .unavailable
        #endif
    }
    func generateKey() async throws -> String {
        #if canImport(DeviceCheck)
        return try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.generateKey { keyID, error in
                if let error { continuation.resume(throwing: Self.map(error)); return }
                guard let keyID, !keyID.isEmpty else { continuation.resume(throwing: AppAttestError.malformedProviderResponse); return }
                continuation.resume(returning: keyID)
            }
        }
        #else
        throw AppAttestError.unavailable
        #endif
    }
    func attest(keyID: String, challengeHash: Data) async throws -> Data {
        #if canImport(DeviceCheck)
        return try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.attestKey(keyID, clientDataHash: challengeHash) { object, error in
                Self.complete(continuation, object: object, error: error)
            }
        }
        #else
        throw AppAttestError.unavailable
        #endif
    }
    func assertion(keyID: String, challengeHash: Data) async throws -> Data {
        #if canImport(DeviceCheck)
        return try await withCheckedThrowingContinuation { continuation in
            DCAppAttestService.shared.generateAssertion(keyID, clientDataHash: challengeHash) { object, error in
                Self.complete(continuation, object: object, error: error)
            }
        }
        #else
        throw AppAttestError.unavailable
        #endif
    }
    nonisolated private static func complete(_ continuation: CheckedContinuation<Data, Error>, object: Data?, error: Error?) {
        if let error { continuation.resume(throwing: map(error)); return }
        guard let object, !object.isEmpty else { continuation.resume(throwing: AppAttestError.malformedProviderResponse); return }
        continuation.resume(returning: object)
    }
    nonisolated private static func map(_ error: Error) -> AppAttestError {
        #if canImport(DeviceCheck)
        let nsError = error as NSError
        if nsError.domain == DCError.errorDomain {
            switch DCError.Code(rawValue: nsError.code) {
            case .featureUnsupported: return .unsupported
            case .serverUnavailable: return .serverUnavailable
            case .invalidKey: return .invalidKey
            default: break
            }
        }
        #endif
        return .providerFailure
    }
}
