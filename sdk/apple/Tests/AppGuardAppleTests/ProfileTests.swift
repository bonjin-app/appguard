import XCTest
import CryptoKit
@testable import AppGuardApple

final class ProfileTests: XCTestCase {
    // Removing byte preservation, syntax checks, or parameter order breaks corpus expectations.
    func testAllFortyCoreCorpusCanonicalBases() throws {
        let rows = try corpus()
        XCTAssertEqual(rows.count, 40)
        for row in rows {
            let request = try fixtureRequest(row)
            let parameters = try fixtureParameters(row)
            let context = row["context"] as! [String: Any]
            if let expected = row["expected_signature_base"] as? String {
                XCTAssertEqual(try RequestProfile.signatureBase(request, parameters: parameters,
                    origin: context["origin"] as! String), Data(expected.utf8), row["id"] as! String)
            } else {
                XCTAssertThrowsError(try RequestProfile.signatureBase(request, parameters: parameters,
                    origin: context["origin"] as! String), row["id"] as! String)
            }
        }
    }

    // This checks fixed raw signatures with a separate native CryptoKit verification API.
    func testFixedCorpusSuccessfulSignaturesWithCryptoKit() throws {
        let rows = try corpus().filter { ($0["expected_codes"] as! [String]).first == "VERIFIED" }
        XCTAssertEqual(rows.count, 6)
        for row in rows {
            let key = row["key"] as! [String: Any]
            let publicKey = try P256.Signing.PublicKey(pemRepresentation: key["public_key_pem"] as! String)
            let raw = Data(base64Encoded: row["signature_b64"] as! String)!
            let der = try P256WireSignature.der(fromRaw: raw)
            XCTAssertTrue(publicKey.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: der),
                for: Data((row["expected_signature_base"] as! String).utf8)))
            XCTAssertEqual(try P256WireSignature.raw(fromDER: der), raw)
        }
    }

    func testFreshEphemeralSignaturesAndExactWireHeaders() throws {
        let key = EphemeralKey()
        let preparer = try RequestPreparer(origin: "https://api.example.test")
        let row = try corpus()[0]
        let p = try fixtureParameters(row)
        let signed = try preparer.prepare(unsigned(), parameters: p, now: 1_700_000_000, key: key)
        XCTAssertEqual(signed.request.target, "/v1/items?b=2&a=1")
        XCTAssertEqual(signed.request.body, Data("{}".utf8))
        XCTAssertEqual(signed.request.headers.map(\.name), ["Content-Type", "Content-Digest", "Authorization",
            "AppGuard-App-Id", "Signature-Input", "Signature"])
        XCTAssertEqual(signed.request.headers[1].value, "sha-256=:RBNvo1WzZ4oRRq0W9+hknpT7T8If536DEMBg9hyq/4o=:")
        let base = row["expected_signature_base"] as! String
        XCTAssertEqual(signed.signatureBase, Data(base.utf8))
        let parameterString = base.components(separatedBy: "\"@signature-params\": ").last!
        XCTAssertEqual(signed.request.headers[4].value, "appguard=" + parameterString)
        XCTAssertEqual(signed.request.headers[5].value, "appguard=:" + signed.signature.base64EncodedString() + ":")
        XCTAssertEqual(signed.signature.count, 64)
        XCTAssertTrue(key.privateKey.publicKey.isValidSignature(
            try P256.Signing.ECDSASignature(rawRepresentation: signed.signature), for: signed.signatureBase))
    }

    func testTargetQueryPercentEscapeAndExplicitEmptyQueryArePreserved() throws {
        let preparer = try RequestPreparer(origin: "https://api.example.test:8443")
        let key = EphemeralKey()
        for target in ["/x?", "/x?x=2&x=1", "/a%2fb?z=%2F&a=", "/?a=%FF"] {
            let result = try preparer.prepare(unsigned(target: target), parameters: params(), now: now, key: key)
            XCTAssertEqual(result.request.target, target)
            XCTAssertTrue(String(decoding: result.signatureBase, as: UTF8.self).contains("https://api.example.test:8443" + target + "\n"))
        }
    }

    func testInvalidTargetsHeadersOriginsAndBodyAreRejectedBeforeKeyUse() throws {
        let key = RejectingKey()
        let preparer = try RequestPreparer(origin: "https://api.example.test")
        for target in ["", "//evil.test/x", "https://evil.test/x", "/x#f", "/a b", "/a\\b", "/%", "/%0G",
                       "/%00", "/%7F", "/%5c", "/a/../x", "/%2e/x", "/a%2f..%2fx", "/é", "/" + String(repeating: "a", count: 8192)] {
            XCTAssertThrowsError(try preparer.prepare(unsigned(target: target), parameters: params(), now: now, key: key))
        }
        for origin in ["http://api.test", "https://API.test", "https://api.test/", "https://user@api.test", "https://api.test:443",
                       "https://api.test:0", "https://api.test:65536", "https://-api.test", "https://api..test", "https://api.test?", "https://[::1]"] {
            XCTAssertThrowsError(try RequestPreparer(origin: origin))
        }
        for request in [unsigned(method: "post"), unsigned(method: String(repeating: "A", count: 33)),
                        unsigned(contentType: ""), unsigned(contentType: " text/plain"), unsigned(contentType: "text/plain\r\nx: y"),
                        unsigned(authorization: "Bearer "), unsigned(authorization: "Bearer a b"), unsigned(appID: "bad app"),
                        unsigned(body: Data(repeating: 0, count: 1_048_577)),
                        unsigned(additional: [HTTPHeader("authorization", "Bearer OTHER")]),
                        unsigned(additional: [HTTPHeader("Signature", "appguard=:AA==:")]),
                        unsigned(additional: [HTTPHeader("Content-Encoding", "gzip")]),
                        unsigned(additional: [HTTPHeader("Content-Length", "1")]),
                        unsigned(additional: [HTTPHeader("X-A", "a\t")]),
                        unsigned(additional: [HTTPHeader("X-A", "é")]),
                        unsigned(additional: [HTTPHeader("Bad Name", "a")]),
                        unsigned(additional: Array(repeating: HTTPHeader("X", "a"), count: 59)),
                        unsigned(additional: [HTTPHeader("X", String(repeating: "a", count: 16_000))])] {
            XCTAssertThrowsError(try preparer.prepare(request, parameters: params(), now: now, key: key))
        }
        XCTAssertEqual(key.calls, 0)
    }

    func testTimestampNonceAndKeyIdentifiersFailBeforeSigning() throws {
        let key = RejectingKey()
        let preparer = try RequestPreparer(origin: "https://api.example.test")
        let invalid = [params(created: -1), params(expires: 1_000_000_000_000_000), params(expires: now),
            params(created: now, expires: now), params(expires: now + 121), params(created: now + 31, expires: now + 120),
            params(nonce: "AAECAwQFBgcICQoLDA0ODx"), params(nonce: "AAECAwQFBgcICQoLDA0ODw=="),
            params(keyID: ""), params(keyID: "bad\"key"), params(algorithm: "rsa"), params(tag: "other")]
        for p in invalid { XCTAssertThrowsError(try preparer.prepare(unsigned(), parameters: p, now: now, key: key)) }
        XCTAssertThrowsError(try preparer.prepare(unsigned(), parameters: params(), now: -1, key: key))
        XCTAssertEqual(key.calls, 0)
        XCTAssertNoThrow(try preparer.prepare(unsigned(), parameters: params(created: now + 30, expires: now + 120), now: now, key: EphemeralKey()))
    }

    func testMaximumBodyAndTargetAndTimestampBoundaries() throws {
        let preparer = try RequestPreparer(origin: "https://api.example.test")
        let request = unsigned(target: "/" + String(repeating: "a", count: 8191), body: Data(repeating: 0, count: 1_048_576))
        XCTAssertEqual(try preparer.prepare(request, parameters: params(), now: now, key: EphemeralKey()).request.body.count, 1_048_576)
        XCTAssertNoThrow(try preparer.prepare(unsigned(), parameters: params(created: 0, expires: 120), now: 0, key: EphemeralKey()))
        XCTAssertNoThrow(try preparer.prepare(unsigned(), parameters: params(created: 999_999_999_999_879, expires: 999_999_999_999_999), now: 999_999_999_999_879, key: EphemeralKey()))
    }

    func testNonceDefaultsUseSixteenOSRandomBytesAndCanonicalURLBase64() throws {
        let first = try SignatureParameters.fresh(keyID: "key", now: now)
        let second = try SignatureParameters.fresh(keyID: "key", now: now)
        XCTAssertEqual(first.created, now)
        XCTAssertEqual(first.expires, now + 120)
        XCTAssertEqual(first.nonce.count, 22)
        XCTAssertNotEqual(first.nonce, second.nonce)
        XCTAssertNoThrow(try RequestProfile.signatureBase(try fixtureRequest(corpus()[0]), parameters: first, origin: "https://api.example.test"))
        XCTAssertThrowsError(try SignatureParameters.fresh(keyID: "key", now: now, lifetime: 121))
        XCTAssertThrowsError(try SignatureParameters.fresh(keyID: "key", now: Int64.max))
    }

    func testExternalMutableBodyAndReturnedDataCannotChangeSignedRequest() throws {
        let storage = UnsafeMutableRawPointer.allocate(byteCount: 4096, alignment: 1)
        defer { storage.deallocate() }
        storage.initializeMemory(as: UInt8.self, repeating: 7, count: 4096)
        let borrowed = Data(bytesNoCopy: storage, count: 4096, deallocator: .none)
        let input = unsigned(body: borrowed)
        storage.storeBytes(of: UInt8(0), as: UInt8.self)
        let result = try RequestPreparer(origin: "https://api.example.test").prepare(input, parameters: params(), now: now, key: EphemeralKey())
        XCTAssertEqual(result.request.body, Data(repeating: 7, count: 4096))
        var returned = result.request.body
        returned[0] = 1
        XCTAssertEqual(result.request.body, Data(repeating: 7, count: 4096))
    }

    func testStrictDERRejectsMalformedAndPreservesLeadingZeroScalars() throws {
        // r=0x80 requires a DER sign octet; s=1 requires left zero-padding on the wire.
        var raw = Data(repeating: 0, count: 64)
        raw[0] = 0x80; raw[63] = 1
        let expectedDER = Data([0x30, 0x26, 0x02, 0x21, 0] + Array(raw.prefix(32)) + [0x02, 0x01, 0x01])
        XCTAssertEqual(try P256WireSignature.der(fromRaw: raw), expectedDER)
        XCTAssertEqual(try P256WireSignature.raw(fromDER: expectedDER), raw)
        for bytes: [UInt8] in [[0x30,6,2,1,0,2,1,1], [0x30,6,2,1,0x80,2,1,1],
                              [0x30,7,2,2,0,1,2,1,1], [0x30,0x81,6,2,1,1,2,1,1],
                              [0x30,6,2,1,1,2,1,1,0], [0x30,3,2,0,1], []] {
            XCTAssertThrowsError(try P256WireSignature.raw(fromDER: Data(bytes)))
        }
        for invalid in [Data(), Data(repeating: 0, count: 64), Data(repeating: 255, count: 64), Data(repeating: 1, count: 63)] {
            XCTAssertThrowsError(try P256WireSignature.der(fromRaw: invalid))
        }
    }

    func testWrongLengthSigningOutputIsRejected() throws {
        XCTAssertThrowsError(try RequestPreparer(origin: "https://api.example.test").prepare(unsigned(), parameters: params(), now: now, key: ShortKey()))
    }
}

let now: Int64 = 1_700_000_000
func params(created: Int64 = now, expires: Int64 = now + 120, nonce: String = "AAECAwQFBgcICQoLDA0ODw", keyID: String = "test-key",
            algorithm: String = "ecdsa-p256-sha256", tag: String = "appguard-request-v0") -> SignatureParameters {
    SignatureParameters(created: created, expires: expires, nonce: nonce, keyID: keyID, algorithm: algorithm, tag: tag)
}
func unsigned(method: String = "POST", target: String = "/v1/items?b=2&a=1", body: Data = Data("{}".utf8),
              contentType: String = "application/json", authorization: String = "Bearer TEST_ONLY_TOKEN", appID: String = "test-app",
              additional: [HTTPHeader] = []) -> UnsignedRequest {
    UnsignedRequest(method: method, target: target, body: body, contentType: contentType, authorization: authorization, appID: appID, additionalHeaders: additional)
}
func corpus() throws -> [[String: Any]] {
    var root = URL(fileURLWithPath: #filePath)
    for _ in 0..<5 { root.deleteLastPathComponent() }
    return try JSONSerialization.jsonObject(with: Data(contentsOf: root.appendingPathComponent("conformance/v0/requests.json"))) as! [[String: Any]]
}
func fixtureRequest(_ row: [String: Any]) throws -> RequestInput {
    let r = row["request"] as! [String: Any]
    return RequestInput(method: r["method"] as! String, target: r["target"] as! String,
        headers: (r["headers"] as! [[String]]).map { HTTPHeader($0[0], $0[1]) }, body: Data(base64Encoded: r["body_b64"] as! String)!)
}
func fixtureParameters(_ row: [String: Any]) throws -> SignatureParameters {
    let p = row["parameters"] as! [String: Any]
    return SignatureParameters(created: (p["created"] as! NSNumber).int64Value, expires: (p["expires"] as! NSNumber).int64Value,
        nonce: p["nonce"] as! String, keyID: p["key_id"] as! String, algorithm: p["algorithm"] as! String, tag: p["tag"] as! String)
}
final class EphemeralKey: RequestSigningKey {
    let privateKey = P256.Signing.PrivateKey()
    func sign(signatureBase: Data) throws -> Data { try privateKey.signature(for: signatureBase).rawRepresentation }
    func publicKeyPEM() throws -> String { privateKey.publicKey.pemRepresentation }
}
final class RejectingKey: RequestSigningKey {
    var calls = 0
    func sign(signatureBase: Data) throws -> Data { calls += 1; throw AppGuardError.signingFailed }
    func publicKeyPEM() throws -> String { throw AppGuardError.signingFailed }
}
struct ShortKey: RequestSigningKey {
    func sign(signatureBase: Data) throws -> Data { Data(repeating: 1, count: 63) }
    func publicKeyPEM() throws -> String { "" }
}
