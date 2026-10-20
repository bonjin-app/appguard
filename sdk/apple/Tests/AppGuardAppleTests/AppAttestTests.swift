import XCTest
@testable import AppGuardApple

@MainActor final class AppAttestTests: XCTestCase {
    func testConfiguredAppIdentifierAndChallengeHashAreValidatedBeforeProviderUse() async throws {
        for appID in ["", "test-app", "ABCDEFGHIJ.", "ABCDEFGHIJ.bad app"] {
            XCTAssertThrowsError(try AppAttestConfiguration(appID: appID, environment: .development))
        }
        let provider = FakeAppAttestService()
        let client = AppAttestClient(configuration: try configuration(), service: provider)
        for hash in [Data(), Data(repeating: 0, count: 31), Data(repeating: 0, count: 33)] {
            do { _ = try await client.attest(keyID: "apple-key", challengeHash: hash); XCTFail("Accepted invalid hash") }
            catch { XCTAssertEqual(error as? AppAttestError, .invalidChallengeHash) }
        }
        do { _ = try await client.assertion(keyID: "", challengeHash: Data(repeating: 0, count: 32)); XCTFail("Accepted empty key") }
        catch { XCTAssertEqual(error as? AppAttestError, .invalidKeyIdentifier) }
        XCTAssertEqual(provider.calls, [])
    }
    func testUnsupportedAndUnavailableRemainExplicitWithoutProviderCalls() async throws {
        for support in [AppAttestSupport.unsupported, .unavailable] {
            let service = FakeAppAttestService(); service.support = support
            let client = AppAttestClient(configuration: try configuration(), service: service)
            XCTAssertEqual(client.support, support)
            do { _ = try await client.generateKey(); XCTFail("Used unsupported provider") }
            catch { XCTAssertEqual(error as? AppAttestError, support == .unsupported ? .unsupported : .unavailable) }
            XCTAssertEqual(service.calls, [])
        }
    }
    func testOpaqueAcquisitionPreservesAppEnvironmentAndHashAndDoesNotClaimVerification() async throws {
        let service = FakeAppAttestService()
        let client = AppAttestClient(configuration: try configuration(), service: service)
        let generatedKey = try await client.generateKey()
        XCTAssertEqual(generatedKey, "apple-key")
        let hash = Data(repeating: 7, count: 32)
        let attest = try await client.attest(keyID: "apple-key", challengeHash: hash)
        let assertion = try await client.assertion(keyID: "apple-key", challengeHash: hash)
        XCTAssertEqual(attest.appID, "ABCDEFGHIJ.com.example.app")
        XCTAssertEqual(attest.environment, .development)
        XCTAssertEqual(attest.operation, .attestation)
        XCTAssertEqual(assertion.operation, .assertion)
        XCTAssertEqual(attest.keyID, "apple-key")
        XCTAssertEqual(attest.challengeHash, hash)
        XCTAssertEqual(attest.opaqueObject, Data([1, 2, 3]))
        XCTAssertEqual(service.lastHash, hash)
        XCTAssertEqual(service.calls, ["key", "attest:apple-key", "assertion:apple-key"])
    }
    func testProviderFailuresAndEmptyResponsesCannotBecomeEvidenceOrRotateKeys() async throws {
        let service = FakeAppAttestService()
        let client = AppAttestClient(configuration: try configuration(), service: service)
        service.failure = .serverUnavailable
        do { _ = try await client.attest(keyID: "keep-key", challengeHash: Data(repeating: 1, count: 32)); XCTFail("Swallowed provider error") }
        catch { XCTAssertEqual(error as? AppAttestError, .serverUnavailable) }
        XCTAssertEqual(service.calls, ["attest:keep-key"])
        service.failure = nil; service.response = Data()
        do { _ = try await client.assertion(keyID: "keep-key", challengeHash: Data(repeating: 1, count: 32)); XCTFail("Accepted empty provider evidence") }
        catch { XCTAssertEqual(error as? AppAttestError, .malformedProviderResponse) }
    }
    private func configuration() throws -> AppAttestConfiguration {
        try AppAttestConfiguration(appID: "ABCDEFGHIJ.com.example.app", environment: .development)
    }
}
@MainActor final class FakeAppAttestService: AppAttestService {
    var support = AppAttestSupport.supported
    var calls: [String] = []; var lastHash: Data?; var failure: AppAttestError?; var response = Data([1,2,3])
    func generateKey() async throws -> String { calls.append("key"); if let error = failure { throw error }; return "apple-key" }
    func attest(keyID: String, challengeHash: Data) async throws -> Data {
        calls.append("attest:" + keyID); lastHash = challengeHash; if let error = failure { throw error }; return response
    }
    func assertion(keyID: String, challengeHash: Data) async throws -> Data {
        calls.append("assertion:" + keyID); lastHash = challengeHash; if let error = failure { throw error }; return response
    }
}
