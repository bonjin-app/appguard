import XCTest
import CryptoKit
@testable import AppGuardApple

/// All keys are ephemeral CryptoKit keys; no persistent Keychain I/O occurs.
final class NativeBridgeTests: XCTestCase {
    let bridgeNow: Int64 = 1_700_000_000
    func common() -> [String: Any] { ["alias": "test-installation", "hardwareRequirement": "any"] }
    func request() -> [String: Any] {
        common().merging(["origin": "https://api.example.test", "method": "POST", "target": "/v1/items?b=2&a=1&a=%2f?",
            "bodyBase64": "AP+AQQ==", "contentType": "application/octet-stream", "authorization": "Bearer TEST_ONLY_TOKEN",
            "appId": "test-app", "keyId": "test-key", "created": bridgeNow, "expires": bridgeNow + 120,
            "nonce": "AAECAwQFBgcICQoLDA0ODw"]) { _, new in new }
    }
    func json(_ value: [String: Any]) throws -> String { String(decoding: try JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]), as: UTF8.self) }
    func success(_ text: String, file: StaticString = #filePath, line: UInt = #line) throws -> [String: Any] {
        let out = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any], file: file, line: line)
        XCTAssertEqual(out["ok"] as? Bool, true, text, file: file, line: line)
        return try XCTUnwrap(out["result"] as? [String: Any], file: file, line: line)
    }
    func error(_ code: String, _ text: String, file: StaticString = #filePath, line: UInt = #line) throws {
        let out = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any], file: file, line: line)
        XCTAssertEqual(Set(out.keys), ["ok", "error"], file: file, line: line); XCTAssertEqual(out["ok"] as? Bool, false, file: file, line: line)
        let failure = try XCTUnwrap(out["error"] as? [String: String], file: file, line: line)
        XCTAssertEqual(failure, ["code": code], file: file, line: line)
    }
    func bridge(_ key: EphemeralKey, load: @escaping () -> Void = {}) -> NativeBridge {
        NativeBridge(keyProvider: { _, _ in load(); return (key, .keychain) }, clock: { self.bridgeNow })
    }
    func enrollment(_ key: EphemeralKey) -> [String: Any] {
        common().merging(["challenge": ["appId": "test-app", "origin": "https://api.example.test", "subject": "test-user", "keyId": "test-key",
            "publicKeySha256": SHA256.hash(data: key.privateKey.publicKey.derRepresentation).map { String(format: "%02x", $0) }.joined(),
            "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "expires": bridgeNow + 120],
            "expectedAppId": "test-app", "expectedOrigin": "https://api.example.test", "expectedSubject": "test-user", "expectedKeyId": "test-key"]) { _, new in new }
    }
    func testBinaryTargetAndOrderedHeadersIndependentlyVerify() throws {
        let key = EphemeralKey(); var loads = 0; let bridge = bridge(key, load: { loads += 1 })
        let out = try success(bridge.invoke(operation: "prepare", payload: json(request())))
        XCTAssertEqual(out["origin"] as? String, "https://api.example.test"); XCTAssertEqual(out["target"] as? String, "/v1/items?b=2&a=1&a=%2f?")
        XCTAssertEqual(out["bodyBase64"] as? String, "AP+AQQ=="); XCTAssertEqual(out["method"] as? String, "POST"); XCTAssertEqual(out["keyId"] as? String, "test-key")
        let headers = try XCTUnwrap(out["headers"] as? [[String]])
        XCTAssertEqual(headers.map { $0[0] }, ["Content-Type", "Content-Digest", "Authorization", "AppGuard-App-Id", "Signature-Input", "Signature"])
        XCTAssertTrue(headers.allSatisfy { $0.count == 2 })
        let digest = "sha-256=:" + Data(SHA256.hash(data: Data([0, 255, 128, 65]))).base64EncodedString() + ":"
        XCTAssertEqual(headers[1][1], digest)
        let params = "(\"@method\" \"@target-uri\" \"content-type\" \"content-digest\" \"authorization\" \"appguard-app-id\");created=1700000000;expires=1700000120;nonce=\"AAECAwQFBgcICQoLDA0ODw\";keyid=\"test-key\";alg=\"ecdsa-p256-sha256\";tag=\"appguard-request-v0\""
        XCTAssertEqual(headers[4][1], "appguard=" + params)
        let literal = "\"@method\": POST\n\"@target-uri\": https://api.example.test/v1/items?b=2&a=1&a=%2f?\n\"content-type\": application/octet-stream\n\"content-digest\": " + digest + "\n\"authorization\": Bearer TEST_ONLY_TOKEN\n\"appguard-app-id\": test-app\n\"@signature-params\": " + params
        let raw = try XCTUnwrap(Data(base64Encoded: String(headers[5][1].dropFirst(10).dropLast())))
        XCTAssertTrue(key.privateKey.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: raw), for: Data(literal.utf8)))
        XCTAssertEqual(loads, 1)
        var empty = request(); empty["target"] = "/x?"; empty["bodyBase64"] = ""
        let emptyOut = try success(bridge.invoke(operation: "prepare", payload: json(empty)))
        XCTAssertEqual(emptyOut["target"] as? String, "/x?"); XCTAssertEqual(emptyOut["bodyBase64"] as? String, "")
    }
    func testPublicKeyReturnsOnlyPublicPemAndExplicitNativeBacking() throws {
        let key = EphemeralKey(); let out = try success(bridge(key).invoke(operation: "publicKey", payload: json(common())))
        XCTAssertEqual(Set(out.keys), ["publicKeyPem", "backing"]); XCTAssertEqual(out["backing"] as? String, "keychain")
        let pem = try XCTUnwrap(out["publicKeyPem"] as? String)
        XCTAssertEqual(try P256.Signing.PublicKey(pemRepresentation: pem).derRepresentation, key.privateKey.publicKey.derRepresentation)
    }
    func testEnrollmentProofIndependentlyVerifiesExactChallengeAndHashes() throws {
        let key = EphemeralKey(); let input = enrollment(key); let out = try success(bridge(key).invoke(operation: "enrollmentProof", payload: json(input)))
        let challenge = try XCTUnwrap(input["challenge"] as? [String: Any]); let fingerprint = try XCTUnwrap(challenge["publicKeySha256"] as? String)
        let message = Data(("appguard-enrollment-v0\napp-id: test-app\norigin: https://api.example.test\nsubject: test-user\nkey-id: test-key\npublic-key-sha256: " + fingerprint + "\nchallenge: AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8\nexpires: 1700000120").utf8)
        let proof = try XCTUnwrap(Data(base64Encoded: try XCTUnwrap(out["proofBase64"] as? String)))
        XCTAssertTrue(key.privateKey.publicKey.isValidSignature(try P256.Signing.ECDSASignature(rawRepresentation: proof), for: message))
        let hash = Data(SHA256.hash(data: message)); XCTAssertEqual(out["clientDataHashBase64"] as? String, hash.base64EncodedString())
        XCTAssertEqual(out["googleRequestHash"] as? String, hash.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: ""))
    }
    func testMalformedTypesEncodingsAndNumericAmbiguityRejectBeforeLookup() throws {
        var loads = 0; let bridge = bridge(EphemeralKey(), load: { loads += 1 })
        var invalid = ["", "[]", "null", "{}", "{'alias':'x'}", "{alias:1}", try json(common()) + "x",
            "{\"alias\":\"x\",\"alias\":\"y\",\"hardwareRequirement\":\"any\"}",
            "{\"alias\":\"x\",\"\\u0061lias\":\"y\",\"hardwareRequirement\":\"any\"}",
            "{\"alias\":\"\\ud800\",\"hardwareRequirement\":\"any\"}", "{\"alias\":\"x\",\"hardwareRequirement\":\"any\",}"]
        for value in [1, true, NSNull(), []] as [Any] { var p = common(); p["alias"] = value; invalid.append(try json(p)) }
        var p = common(); p["privateKey"] = "secret"; invalid.append(try json(p)); p = common(); p["hardwareRequirement"] = "software"; invalid.append(try json(p))
        for payload in invalid { try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "publicKey", payload: payload)) }
        for body in ["AA", "AB==", "AA==\n", "_-8=", "A===", "!"] { var p = request(); p["bodyBase64"] = body; try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "prepare", payload: json(p))) }
        for field in ["created", "expires"] {
            for number in ["true", "null", "1.0", "1e3", "01", "-1", "1000000000000000", "9999999999999999999999", "\"1700000000\""] {
                let original = "\"" + field + "\":" + String(field == "created" ? bridgeNow : bridgeNow + 120)
                let payload = try json(request()).replacingOccurrences(of: original, with: "\"" + field + "\":" + number)
                try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "prepare", payload: payload))
            }
        }
        for field in ["origin", "method", "target", "contentType", "authorization", "appId", "keyId", "nonce"] {
            var p = request(); p[field] = "\ninvalid"; try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "prepare", payload: json(p)))
        }
        var future = request(); future["created"] = bridgeNow + 31; future["expires"] = bridgeNow + 100
        try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "prepare", payload: json(future)))
        var expired = request(); expired["created"] = bridgeNow - 120; expired["expires"] = bridgeNow
        try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "prepare", payload: json(expired)))
        var clock = request(); clock["now"] = bridgeNow; try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "prepare", payload: json(clock)))
        XCTAssertEqual(loads, 0)
    }
    func testInvalidEnrollmentBindingsUnknownAndDuplicateChallengeRejectBeforeLookup() throws {
        let key = EphemeralKey(); var loads = 0; let bridge = bridge(key, load: { loads += 1 })
        for field in ["expectedAppId", "expectedOrigin", "expectedSubject", "expectedKeyId"] {
            var p = enrollment(key); p[field] = field == "expectedOrigin" ? "https://other.test" : "other"
            try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "enrollmentProof", payload: json(p)))
        }
        var p = enrollment(key); var challenge = try XCTUnwrap(p["challenge"] as? [String: Any]); challenge["expires"] = bridgeNow; p["challenge"] = challenge
        try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "enrollmentProof", payload: json(p)))
        challenge["unexpected"] = "x"; p["challenge"] = challenge; try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "enrollmentProof", payload: json(p)))
        let duplicate = try json(enrollment(key)).replacingOccurrences(of: "\"subject\":\"test-user\"", with: "\"subject\":\"test-user\",\"subject\":\"other\"")
        try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "enrollmentProof", payload: duplicate)); XCTAssertEqual(loads, 0)
    }
    func testBoundsAndUnsupportedOperationsAndHardwareBeforeLookup() throws {
        var loads = 0; let bridge = bridge(EphemeralKey(), load: { loads += 1 })
        try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "publicKey", payload: String(repeating: " ", count: 1_500_001)))
        var p = common(); p["alias"] = String(repeating: "é", count: 750_000); try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "publicKey", payload: json(p)))
        p = request(); p["bodyBase64"] = Data(repeating: 0, count: 1_048_577).base64EncodedString(); try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "prepare", payload: json(p)))
        for operation in ["sign", "privateKey", "attest", ""] { try error("APPGUARD_UNSUPPORTED", bridge.invoke(operation: operation, payload: json(common()))) }
        p = common(); p["hardwareRequirement"] = "strongbox"; try error("APPGUARD_UNSUPPORTED", bridge.invoke(operation: "publicKey", payload: json(p)))
        XCTAssertEqual(loads, 0)
    }
    func testExactBodyAndUtf8JsonLimitsAndDefaultNativeClock() throws {
        let bridge = bridge(EphemeralKey()); var p = request()
        let encoded = Data(repeating: 0, count: 1_048_576).base64EncodedString(); p["bodyBase64"] = encoded
        XCTAssertEqual(try success(bridge.invoke(operation: "prepare", payload: json(p)))["bodyBase64"] as? String, encoded)
        let small = try json(common())
        _ = try success(bridge.invoke(operation: "publicKey", payload: small + String(repeating: " ", count: 1_500_000 - small.utf8.count)))
        try error("APPGUARD_INVALID_INPUT", bridge.invoke(operation: "publicKey", payload: small + String(repeating: " ", count: 1_500_001 - small.utf8.count)))
        // Expired input rejects under the default native clock before any persistent Keychain access.
        try error("APPGUARD_INVALID_INPUT", NativeBridge().invoke(operation: "prepare", payload: json(request())))
    }
    func testHardwareRequirementReachesProviderAndKeyFailuresAreRedacted() throws {
        var hardware: Bool?; let key = EphemeralKey()
        let bridge = NativeBridge(keyProvider: { _, required in hardware = required; return (key, required ? .secureEnclave : .keychain) }, clock: { self.bridgeNow })
        var p = common(); p["hardwareRequirement"] = "hardware"
        XCTAssertEqual(try success(bridge.invoke(operation: "publicKey", payload: json(p)))["backing"] as? String, "secureEnclave"); XCTAssertEqual(hardware, true)
        let unavailable = NativeBridge(keyProvider: { _, _ in throw NSError(domain: "Bearer SECRET /private/body", code: 5) }, clock: { self.bridgeNow })
        try error("APPGUARD_KEY_UNAVAILABLE", unavailable.invoke(operation: "publicKey", payload: json(common())))
        try error("APPGUARD_KEY_UNAVAILABLE", unavailable.invoke(operation: "prepare", payload: json(request())))
        let broken = NativeBridge(keyProvider: { _, _ in (BridgeBrokenKey(), .keychain) }, clock: { self.bridgeNow })
        try error("APPGUARD_OPERATION_FAILED", broken.invoke(operation: "prepare", payload: json(request())))
    }
}
private struct BridgeBrokenKey: RequestSigningKey {
    func sign(signatureBase: Data) throws -> Data { throw NSError(domain: "Bearer SECRET", code: 1) }
    func publicKeyPEM() throws -> String { throw NSError(domain: "private key", code: 2) }
}
