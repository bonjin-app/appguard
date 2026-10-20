import XCTest
import CryptoKit
@testable import AppGuardApple

final class EnrollmentTests: XCTestCase {
    func testLiteralDomainSeparatedChallengeMessage() throws {
        let challenge = makeChallenge(fingerprint: "3b99f4d208b94c14486b08d21ba830cd2af8e683882e282498372af1cae965c3")
        let literal = "appguard-enrollment-v0\napp-id: test-app\norigin: https://api.example.test\nsubject: test-user\nkey-id: test-key\npublic-key-sha256: 3b99f4d208b94c14486b08d21ba830cd2af8e683882e282498372af1cae965c3\nchallenge: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\nexpires: 1700000120"
        XCTAssertEqual(try challenge.canonicalMessage(), Data(literal.utf8))
        XCTAssertFalse(try challenge.canonicalMessage().last == 10)
    }
    func testProofAndAppAttestHashBindEphemeralInstallationPublicKey() throws {
        let key = EphemeralKey()
        let publicKey = key.privateKey.publicKey
        let fingerprint = SHA256.hash(data: publicKey.derRepresentation).map { String(format: "%02x", $0) }.joined()
        let challenge = makeChallenge(fingerprint: fingerprint)
        let proof = try create(challenge, key: key)
        XCTAssertEqual(proof.publicKeyPEM, try key.publicKeyPEM())
        XCTAssertEqual(proof.proof.count, 64)
        XCTAssertEqual(proof.clientDataHash, Data(SHA256.hash(data: proof.message)))
        XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: proof.proof), for: proof.message))
        XCTAssertEqual(proof.message, try challenge.canonicalMessage())
    }
    func testWrongBindingsMalformedNonceAndExpiryRejectBeforeSigning() throws {
        let key = CountingEphemeralKey()
        let goodHash = SHA256.hash(data: key.key.privateKey.publicKey.derRepresentation).map { String(format: "%02x", $0) }.joined()
        for challenge in [makeChallenge(appID: "other-app", fingerprint: goodHash),
                          makeChallenge(subject: "other-user", fingerprint: goodHash),
                          makeChallenge(keyID: "other-key", fingerprint: goodHash),
                          makeChallenge(origin: "https://evil.example.test", fingerprint: goodHash),
                          makeChallenge(fingerprint: "ABC"), makeChallenge(fingerprint: goodHash, nonce: "bad"),
                          makeChallenge(fingerprint: goodHash, nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9"),
                          makeChallenge(fingerprint: goodHash, expires: now), makeChallenge(fingerprint: goodHash, expires: now + 301),
                          makeChallenge(subject: "user\ninject", fingerprint: goodHash)] {
            XCTAssertThrowsError(try create(challenge, key: key))
        }
        XCTAssertEqual(key.calls, 0)
        XCTAssertEqual(key.publicReads, 0)
    }
    func testWrongPublicKeyFingerprintAndMalformedPublicKeyCannotSign() throws {
        let key = CountingEphemeralKey()
        XCTAssertThrowsError(try create(makeChallenge(fingerprint: String(repeating: "a", count: 64)), key: key))
        XCTAssertEqual(key.calls, 0)
        XCTAssertThrowsError(try create(makeChallenge(fingerprint: String(repeating: "a", count: 64)), key: ShortKey()))
    }
    private func create(_ challenge: EnrollmentChallenge, key: any RequestSigningKey) throws -> EnrollmentProof {
        try EnrollmentProof.create(challenge: challenge, expectedAppID: "test-app", expectedSubject: "test-user",
            expectedKeyID: "test-key", expectedOrigin: "https://api.example.test", now: now, key: key)
    }
}
func makeChallenge(appID: String = "test-app", subject: String = "test-user", keyID: String = "test-key",
                   origin: String = "https://api.example.test", fingerprint: String,
                   nonce: String = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", expires: Int64 = now + 120) -> EnrollmentChallenge {
    EnrollmentChallenge(appID: appID, origin: origin, subject: subject, keyID: keyID, publicKeySHA256: fingerprint, nonce: nonce, expires: expires)
}
final class CountingEphemeralKey: RequestSigningKey {
    let key = EphemeralKey(); var calls = 0; var publicReads = 0
    func sign(signatureBase: Data) throws -> Data { calls += 1; return try key.sign(signatureBase: signatureBase) }
    func publicKeyPEM() throws -> String { publicReads += 1; return try key.publicKeyPEM() }
}
