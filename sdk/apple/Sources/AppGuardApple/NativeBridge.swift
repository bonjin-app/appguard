import Foundation

/// Bounded JSON facade over the typed SDK. It exposes no transport, key import/export or arbitrary signing.
public struct NativeBridge {
    private let keyProvider: (String, Bool) throws -> (any RequestSigningKey, InstallationKeyBacking)
    private let clock: () -> Int64
    private let localRiskScanner: (LocalRiskConfiguration) -> LocalRiskReport

    /// Uses installation keys and the native wall clock. There is no bridge-supplied clock/key input.
    public init() {
        self.init(keyProvider: { alias, hardware in
            let key = try InstallationKey.getOrCreate(applicationTag: alias, secureEnclaveRequired: hardware)
            return (key, key.backing)
        }, clock: { Int64(Date().timeIntervalSince1970.rounded(.down)) })
    }
    // Internal seams keep host tests away from persistent user Keychain state.
    init(keyProvider: @escaping (String, Bool) throws -> (any RequestSigningKey, InstallationKeyBacking), clock: @escaping () -> Int64,
         localRiskScanner: @escaping (LocalRiskConfiguration) -> LocalRiskReport = { LocalRiskScanner().scan(configuration: $0) }) {
        self.keyProvider = keyProvider; self.clock = clock; self.localRiskScanner = localRiskScanner
    }

    /// Always returns the fixed response envelope; no underlying exception text is returned.
    public func invoke(operation: String, payload: String) -> String {
        var key: BridgeLazyKey?
        do {
            // Scans validate their separate bounded schema before any key or clock path is reached.
            if operation == "scanLocalRisk" { return try scanLocalRisk(payload) }
            let fields: Set<String>
            switch operation {
            case "publicKey": fields = ["alias", "hardwareRequirement"]
            case "prepare": fields = ["alias", "hardwareRequirement", "origin", "method", "target", "bodyBase64", "contentType",
                "authorization", "appId", "keyId", "created", "expires", "nonce"]
            case "enrollmentProof": fields = ["alias", "hardwareRequirement", "challenge", "expectedAppId", "expectedOrigin", "expectedSubject", "expectedKeyId"]
            default: return failure("APPGUARD_UNSUPPORTED")
            }
            let object = try BridgeJSON.parse(payload)
            try requireFields(object, fields)
            let alias = try string(object, "alias")
            guard (1...256).contains(alias.utf8.count), !alias.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
                throw AppGuardError.invalidRequest
            }
            let hardware: Bool
            switch try string(object, "hardwareRequirement") {
            case "any": hardware = false
            case "hardware": hardware = true
            case "strongbox": return failure("APPGUARD_UNSUPPORTED")
            default: throw AppGuardError.invalidRequest
            }
            let lazy = BridgeLazyKey { try keyProvider(alias, hardware) }; key = lazy
            let result: [String: Any]
            switch operation {
            case "publicKey":
                let handle = try lazy.load()
                result = ["publicKeyPem": try handle.0.publicKeyPEM(), "backing": handle.1.rawValue]
            case "prepare":
                let encoded = try string(object, "bodyBase64")
                guard encoded.utf8.count <= 1_398_104, let body = Data(base64Encoded: encoded),
                      body.count <= 1_048_576, body.base64EncodedString() == encoded else { throw AppGuardError.invalidRequest }
                let origin = try string(object, "origin")
                let input = try UnsignedRequest(method: string(object, "method"), target: string(object, "target"), body: body,
                    contentType: string(object, "contentType"), authorization: string(object, "authorization"), appID: string(object, "appId"))
                let parameters = try SignatureParameters(created: integer(object, "created"), expires: integer(object, "expires"),
                    nonce: string(object, "nonce"), keyID: string(object, "keyId"))
                // RequestPreparer performs syntax, header-budget and clock validation before this lazy key is loaded.
                let signed = try RequestPreparer(origin: origin).prepare(input, parameters: parameters, now: clock(), key: lazy)
                result = ["origin": origin, "method": signed.request.method, "target": signed.request.target,
                    "bodyBase64": signed.request.body.base64EncodedString(), "keyId": signed.parameters.keyID,
                    "headers": signed.request.headers.map { [$0.name, $0.value] }]
            default:
                guard case .object(let challenge)? = object["challenge"] else { throw AppGuardError.invalidRequest }
                try requireFields(challenge, ["appId", "origin", "subject", "keyId", "publicKeySha256", "nonce", "expires"])
                let input = try EnrollmentChallenge(appID: string(challenge, "appId"), origin: string(challenge, "origin"),
                    subject: string(challenge, "subject"), keyID: string(challenge, "keyId"), publicKeySHA256: string(challenge, "publicKeySha256"),
                    nonce: string(challenge, "nonce"), expires: integer(challenge, "expires"))
                let proof = try EnrollmentProof.create(challenge: input, expectedAppID: string(object, "expectedAppId"),
                    expectedSubject: string(object, "expectedSubject"), expectedKeyID: string(object, "expectedKeyId"),
                    expectedOrigin: string(object, "expectedOrigin"), now: clock(), key: lazy)
                result = ["proofBase64": proof.proof.base64EncodedString(), "clientDataHashBase64": proof.clientDataHash.base64EncodedString(),
                    "googleRequestHash": RequestProfile.urlBase64(proof.clientDataHash)]
            }
            let data = try JSONSerialization.data(withJSONObject: ["ok": true, "result": result], options: [.sortedKeys, .withoutEscapingSlashes])
            return String(decoding: data, as: UTF8.self)
        } catch {
            // The typed request preparer deliberately redacts signing errors; retain only the load-failure category.
            if key?.unavailable == true { return failure("APPGUARD_KEY_UNAVAILABLE") }
            switch error {
            case AppGuardError.invalidRequest, AppGuardError.invalidTime, EnrollmentProofError.bindingMismatch, EnrollmentProofError.publicKeyMismatch,
                 LocalRiskError.invalidConfiguration:
                return failure("APPGUARD_INVALID_INPUT")
            case AppGuardError.unsupportedProfile: return failure("APPGUARD_UNSUPPORTED")
            default: return failure("APPGUARD_OPERATION_FAILED")
            }
        }
    }
    private func scanLocalRisk(_ payload: String) throws -> String {
        let object = try BridgeJSON.parse(payload, maxBytes: 8192, allowsStringArrays: true)
        guard Set(object.keys).isSubset(of: ["expectedAppId", "androidSignerSha256", "protectedResources"]) else { throw AppGuardError.invalidRequest }
        let expectedAppID = try object["expectedAppId"].map { _ in try string(object, "expectedAppId") }
        var signers: [String] = []
        if let value = object["androidSignerSha256"] {
            guard case .strings(let values) = value, values.count <= 8, Set(values).count == values.count,
                  values.allSatisfy({ value in
                      value.utf8.count == 64 && value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
                  }) else { throw AppGuardError.invalidRequest }
            signers = values
        }
        var resources: [String: String] = [:]
        if let value = object["protectedResources"] {
            guard case .object(let pins) = value else { throw AppGuardError.invalidRequest }
            for (path, value) in pins {
                guard case .string(let pin) = value else { throw AppGuardError.invalidRequest }
                resources[path] = pin
            }
        }
        let configuration = try LocalRiskConfiguration(expectedAppID: expectedAppID, protectedResources: resources)
        // A configured platform check must never silently become an unconfigured iOS check.
        guard signers.isEmpty else { return failure("APPGUARD_UNSUPPORTED") }
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(BridgeRiskResponse(result: localRiskScanner(configuration)))
        guard data.count <= 4096 else { return failure("APPGUARD_OPERATION_FAILED") }
        return String(decoding: data, as: UTF8.self)
    }
    private func requireFields(_ object: [String: BridgeJSON.Value], _ fields: Set<String>) throws {
        guard Set(object.keys) == fields else { throw AppGuardError.invalidRequest }
    }
    private func string(_ object: [String: BridgeJSON.Value], _ name: String) throws -> String {
        guard case .string(let value)? = object[name] else { throw AppGuardError.invalidRequest }; return value
    }
    private func integer(_ object: [String: BridgeJSON.Value], _ name: String) throws -> Int64 {
        guard case .integer(let value)? = object[name] else { throw AppGuardError.invalidRequest }; return value
    }
    private func failure(_ code: String) -> String { "{\"ok\":false,\"error\":{\"code\":\"" + code + "\"}}" }
}

private struct BridgeRiskResponse: Encodable {
    let ok = true
    let result: LocalRiskReport
}

private final class BridgeLazyKey: RequestSigningKey {
    let provider: () throws -> (any RequestSigningKey, InstallationKeyBacking)
    var handle: (any RequestSigningKey, InstallationKeyBacking)?
    private(set) var unavailable = false
    init(provider: @escaping () throws -> (any RequestSigningKey, InstallationKeyBacking)) { self.provider = provider }
    func load() throws -> (any RequestSigningKey, InstallationKeyBacking) {
        if let handle { return handle }
        do { let loaded = try provider(); handle = loaded; return loaded }
        catch { unavailable = true; throw AppGuardError.signingFailed }
    }
    func sign(signatureBase: Data) throws -> Data { try load().0.sign(signatureBase: signatureBase) }
    func publicKeyPEM() throws -> String { try load().0.publicKeyPEM() }
}

/// Foundation object decoding would erase duplicate keys and numeric spelling, so validate the
/// bounded grammar before coercion. Only scans permit bounded, flat arrays of strings.
private struct BridgeJSON {
    enum Value { case string(String), integer(Int64), object([String: Value]), strings([String]) }
    private let bytes: [UInt8]
    private let allowsStringArrays: Bool
    private var at = 0
    static func parse(_ text: String, maxBytes: Int = 1_500_000, allowsStringArrays: Bool = false) throws -> [String: Value] {
        guard text.utf8.count <= maxBytes else { throw AppGuardError.invalidRequest }
        var parser = BridgeJSON(bytes: Array(text.utf8), allowsStringArrays: allowsStringArrays)
        let result = try parser.object(depth: 0); parser.whitespace()
        guard parser.at == parser.bytes.count else { throw AppGuardError.invalidRequest }; return result
    }
    private mutating func object(depth: Int) throws -> [String: Value] {
        guard depth <= 2 else { throw AppGuardError.invalidRequest }
        whitespace(); try expect(123); whitespace(); var result: [String: Value] = [:]
        if take(125) { return result }
        while true {
            whitespace(); let name = try quoted(); whitespace(); try expect(58); whitespace()
            guard result[name] == nil, at < bytes.count else { throw AppGuardError.invalidRequest }
            let value: Value
            switch bytes[at] {
            case 34: value = .string(try quoted())
            case 123: value = .object(try object(depth: depth + 1))
            case 91 where allowsStringArrays: value = .strings(try stringArray())
            default: value = .integer(try number())
            }
            result[name] = value; whitespace()
            if take(125) { return result }; try expect(44)
        }
    }
    private mutating func stringArray() throws -> [String] {
        try expect(91); whitespace(); var result: [String] = []
        if take(93) { return result }
        while true {
            guard result.count < 8 else { throw AppGuardError.invalidRequest }
            whitespace(); result.append(try quoted()); whitespace()
            if take(93) { return result }; try expect(44)
        }
    }
    private mutating func number() throws -> Int64 {
        let start = at
        while at < bytes.count, 48...57 ~= bytes[at] { at += 1 }
        guard at > start, at - start <= 15, at - start == 1 || bytes[start] != 48,
              let number = Int64(String(decoding: bytes[start..<at], as: UTF8.self)) else { throw AppGuardError.invalidRequest }
        return number
    }
    private mutating func quoted() throws -> String {
        let start = at; try expect(34)
        while at < bytes.count {
            let byte = bytes[at]; at += 1
            guard byte >= 32 else { throw AppGuardError.invalidRequest }
            if byte == 34 {
                do { return try JSONDecoder().decode(String.self, from: Data(bytes[start..<at])) }
                catch { throw AppGuardError.invalidRequest }
            }
            if byte == 92 {
                guard at < bytes.count else { throw AppGuardError.invalidRequest }; at += 1
            }
        }
        throw AppGuardError.invalidRequest
    }
    private mutating func whitespace() { while at < bytes.count, [9, 10, 13, 32].contains(bytes[at]) { at += 1 } }
    private mutating func take(_ byte: UInt8) -> Bool {
        guard at < bytes.count, bytes[at] == byte else { return false }; at += 1; return true
    }
    private mutating func expect(_ byte: UInt8) throws { guard take(byte) else { throw AppGuardError.invalidRequest } }
}
