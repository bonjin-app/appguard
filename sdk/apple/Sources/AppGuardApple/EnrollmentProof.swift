import Foundation
import CryptoKit

/// A typed challenge from the application's authenticated server enrollment flow.
public struct EnrollmentChallenge {
    public let appID: String
    public let origin: String
    public let subject: String
    public let keyID: String
    public let publicKeySHA256: String
    public let nonce: String
    public let expires: Int64
    public init(appID: String, origin: String, subject: String, keyID: String, publicKeySHA256: String, nonce: String, expires: Int64) {
        self.appID = appID; self.origin = origin; self.subject = subject; self.keyID = keyID
        self.publicKeySHA256 = publicKeySHA256; self.nonce = nonce; self.expires = expires
    }
    /// Exact enrollment-v0 bytes, not a verification or authorization result.
    public func canonicalMessage() throws -> Data {
        try RequestProfile.identifier(appID); try RequestProfile.identifier(subject); try RequestProfile.identifier(keyID)
        try RequestProfile.validateOrigin(origin)
        guard RequestProfile.matches(publicKeySHA256, "[0-9a-f]{64}"),
              RequestProfile.matches(nonce, "[A-Za-z0-9_-]{43}"),
              let bytes = Data(base64Encoded: nonce.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "="),
              bytes.count == 32, RequestProfile.urlBase64(bytes) == nonce else { throw AppGuardError.invalidRequest }
        guard expires >= 0, expires <= RequestProfile.maxTimestamp else { throw AppGuardError.invalidTime }
        return Data(("appguard-enrollment-v0\napp-id: " + appID + "\norigin: " + origin + "\nsubject: " + subject +
            "\nkey-id: " + keyID + "\npublic-key-sha256: " + publicKeySHA256 + "\nchallenge: " + nonce + "\nexpires: " + String(expires)).utf8)
    }
}

public enum EnrollmentProofError: Error, Equatable { case bindingMismatch, publicKeyMismatch, invalidPublicKey }

/// Public proof of key possession, with the exact challenge hash for App Attest acquisition.
/// A proof and an opaque App Attest object still require separate server verification.
public struct EnrollmentProof {
    public let proof: Data
    public let message: Data
    public let clientDataHash: Data
    public let publicKeyPEM: String
    public static func create(challenge: EnrollmentChallenge, expectedAppID: String, expectedSubject: String, expectedKeyID: String,
                              expectedOrigin: String, now: Int64? = nil, key: any RequestSigningKey) throws -> EnrollmentProof {
        let message = try challenge.canonicalMessage()
        try RequestProfile.identifier(expectedAppID); try RequestProfile.identifier(expectedSubject); try RequestProfile.identifier(expectedKeyID)
        try RequestProfile.validateOrigin(expectedOrigin)
        guard challenge.appID == expectedAppID, challenge.subject == expectedSubject,
              challenge.keyID == expectedKeyID, challenge.origin == expectedOrigin else { throw EnrollmentProofError.bindingMismatch }
        let clock = try RequestProfile.clock(now)
        guard challenge.expires > clock, challenge.expires - clock <= 300 else { throw AppGuardError.invalidTime }
        let pem = try key.publicKeyPEM()
        guard pem.utf8.count <= 4096, pem.utf8.allSatisfy({ $0 < 128 }) else { throw EnrollmentProofError.invalidPublicKey }
        let publicKey: P256.Signing.PublicKey
        do { publicKey = try P256.Signing.PublicKey(pemRepresentation: pem) }
        catch { throw EnrollmentProofError.invalidPublicKey }
        let fingerprint = SHA256.hash(data: publicKey.derRepresentation).map { String(format: "%02x", $0) }.joined()
        guard fingerprint == challenge.publicKeySHA256 else { throw EnrollmentProofError.publicKeyMismatch }
        let signature: Data
        do { signature = try key.sign(signatureBase: message) }
        catch { throw AppGuardError.signingFailed }
        _ = try P256WireSignature.der(fromRaw: signature)
        guard publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: signature), for: message) else { throw AppGuardError.invalidSignature }
        return EnrollmentProof(proof: Data(Array(signature)), message: message, clientDataHash: Data(SHA256.hash(data: message)), publicKeyPEM: pem)
    }
}
