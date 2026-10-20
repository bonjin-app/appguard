import Foundation
import CryptoKit
import AppGuardApple

// Ephemeral private material exists only in this process. JSON output contains public material only.
private final class EphemeralKey: RequestSigningKey {
    private let key = P256.Signing.PrivateKey()
    func sign(signatureBase: Data) throws -> Data { try key.signature(for: signatureBase).rawRepresentation }
    func publicKeyPEM() throws -> String { key.publicKey.pemRepresentation }
}

var root = URL(fileURLWithPath: #filePath)
for _ in 0..<7 { root.deleteLastPathComponent() }
let enrollmentMode = CommandLine.arguments.contains("--enrollment")
let input = CommandLine.arguments.dropFirst().first(where: { !$0.hasPrefix("--") }).map { URL(fileURLWithPath: $0) } ?? root.appendingPathComponent("conformance/v0/requests.json")
if enrollmentMode {
    let key = EphemeralKey()
    let pem = try key.publicKeyPEM()
    let publicKey = try P256.Signing.PublicKey(pemRepresentation: pem)
    let fingerprint = SHA256.hash(data: publicKey.derRepresentation).map { String(format: "%02x", $0) }.joined()
    let challenge = EnrollmentChallenge(appID: "test-app", origin: "https://api.example.test", subject: "test-user", keyID: "apple-installation-key",
        publicKeySHA256: fingerprint, nonce: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", expires: 1_700_000_120)
    let proof = try EnrollmentProof.create(challenge: challenge, expectedAppID: "test-app", expectedSubject: "test-user", expectedKeyID: "apple-installation-key",
        expectedOrigin: "https://api.example.test", now: 1_700_000_000, key: key)
    let output: [String: Any] = ["challenge": ["app_id": challenge.appID, "origin": challenge.origin, "subject": challenge.subject,
        "key_id": challenge.keyID, "public_key_sha256": challenge.publicKeySHA256, "nonce": challenge.nonce, "expires": challenge.expires],
        "proof_b64": proof.proof.base64EncodedString(), "public_key_pem": pem, "context": ["now": 1_700_000_000]]
    let data = try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
    FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10]))
} else {
let all = try JSONSerialization.jsonObject(with: Data(contentsOf: input)) as! [[String: Any]]
var cases = all.filter { ($0["expected_codes"] as! [String]).first == "VERIFIED" }
var emptyQuery = cases[0]
emptyQuery["id"] = "explicit-empty-query"
var emptyRequest = emptyQuery["request"] as! [String: Any]
emptyRequest["target"] = "/v1/items?"; emptyQuery["request"] = emptyRequest
cases.append(emptyQuery)
var binary = cases[0]
binary["id"] = "raw-binary-body"
var binaryRequest = binary["request"] as! [String: Any]
binaryRequest["body_b64"] = Data([0, 255, 13, 10]).base64EncodedString(); binary["request"] = binaryRequest
cases.append(binary)
let key = EphemeralKey()
let pem = try key.publicKeyPEM()
var output: [[String: Any]] = []
for row in cases {
    let request = row["request"] as! [String: Any]
    let context = row["context"] as! [String: Any]
    let parameters = row["parameters"] as! [String: Any]
    let sourceHeaders = request["headers"] as! [[String]]
    func header(_ name: String) -> String { sourceHeaders.first { $0[0].lowercased() == name }![1] }
    let extras = sourceHeaders.filter { !["content-type", "content-digest", "authorization", "appguard-app-id"].contains($0[0].lowercased()) }.map { HTTPHeader($0[0], $0[1]) }
    let unsigned = UnsignedRequest(method: request["method"] as! String, target: request["target"] as! String,
        body: Data(base64Encoded: request["body_b64"] as! String)!, contentType: header("content-type"),
        authorization: header("authorization"), appID: header("appguard-app-id"), additionalHeaders: extras)
    let p = SignatureParameters(created: (parameters["created"] as! NSNumber).int64Value,
        expires: (parameters["expires"] as! NSNumber).int64Value, nonce: parameters["nonce"] as! String, keyID: parameters["key_id"] as! String)
    let result = try RequestPreparer(origin: context["origin"] as! String).prepare(unsigned, parameters: p,
        now: (context["now"] as! NSNumber).int64Value, key: key)
    var fixture = row
    fixture["id"] = "apple-" + (row["id"] as! String)
    fixture["request"] = ["method": result.request.method, "target": result.request.target,
        "headers": result.request.headers.map { [$0.name, $0.value] }, "body_b64": result.request.body.base64EncodedString()]
    fixture["signature_b64"] = result.signature.base64EncodedString()
    var record = row["key"] as! [String: Any]
    record["public_key_pem"] = pem; fixture["key"] = record
    fixture["expected_signature_base"] = String(decoding: result.signatureBase, as: UTF8.self)
    fixture["expected_codes"] = ["VERIFIED", "REPLAY_DETECTED"]
    fixture["replay_store"] = "memory"
    output.append(fixture)
}
let encoded = try JSONSerialization.data(withJSONObject: output, options: [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes])
FileHandle.standardOutput.write(encoded)
FileHandle.standardOutput.write(Data([10]))

}
