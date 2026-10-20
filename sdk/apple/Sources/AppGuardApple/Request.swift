import Foundation
import CryptoKit
import Security
public enum AppGuardError: Error, Equatable { case invalidRequest, unsupportedProfile, invalidTime, invalidSignature, signingFailed, randomUnavailable }
public struct HTTPHeader: Equatable {
    public let name: String; public let value: String
    public init(_ name: String, _ value: String) { self.name = name; self.value = value }
}
public struct RequestInput {
    public let method: String; public let target: String; public let headers: [HTTPHeader]; public let body: Data
    public init(method: String, target: String, headers: [HTTPHeader], body: Data) {
        self.method = method; self.target = target; self.headers = headers; self.body = Data(Array(body))
    }
}
public struct UnsignedRequest {
    public let method: String; public let target: String; public let body: Data
    public let contentType: String; public let authorization: String; public let appID: String; public let additionalHeaders: [HTTPHeader]
    public init(method: String, target: String, body: Data, contentType: String, authorization: String, appID: String, additionalHeaders: [HTTPHeader] = []) {
        self.method = method; self.target = target; self.body = Data(Array(body)); self.contentType = contentType
        self.authorization = authorization; self.appID = appID; self.additionalHeaders = additionalHeaders
    }
}
public struct SignatureParameters {
    public let created: Int64; public let expires: Int64; public let nonce: String; public let keyID: String
    public let algorithm: String; public let tag: String
    public init(created: Int64, expires: Int64, nonce: String, keyID: String, algorithm: String = "ecdsa-p256-sha256", tag: String = "appguard-request-v0") {
        self.created = created; self.expires = expires; self.nonce = nonce; self.keyID = keyID; self.algorithm = algorithm; self.tag = tag
    }
    public static func fresh(keyID: String, now: Int64? = nil, lifetime: Int64 = 120) throws -> Self {
        let clock = try RequestProfile.clock(now)
        guard lifetime > 0, lifetime <= 120, clock <= RequestProfile.maxTimestamp - lifetime else { throw AppGuardError.invalidTime }
        try RequestProfile.identifier(keyID)
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { throw AppGuardError.randomUnavailable }
        return Self(created: clock, expires: clock + lifetime, nonce: RequestProfile.urlBase64(Data(bytes)), keyID: keyID)
    }
}
public protocol RequestSigningKey {
    func sign(signatureBase: Data) throws -> Data
    func publicKeyPEM() throws -> String
}
public struct SignedRequest {
    public let request: RequestInput; public let parameters: SignatureParameters; public let signature: Data; public let signatureBase: Data
}
/// Binds one explicitly configured external HTTPS origin. Targets never pass through URL normalization.
public struct RequestPreparer {
    public let origin: String
    public init(origin: String) throws {
        try RequestProfile.validateOrigin(origin)
        self.origin = origin
    }
    public func prepare(_ input: UnsignedRequest, parameters: SignatureParameters, now: Int64? = nil, key: any RequestSigningKey) throws -> SignedRequest {
        // Validate all attacker-controlled syntax and final wire limits before hashing or asking a key to sign.
        var headers = [HTTPHeader("Content-Type", input.contentType),
            HTTPHeader("Content-Digest", "sha-256=:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=:"),
            HTTPHeader("Authorization", input.authorization), HTTPHeader("AppGuard-App-Id", input.appID)] + input.additionalHeaders
        let wireSuffix = [HTTPHeader("Signature-Input", "appguard=" + parameters.serialized),
            HTTPHeader("Signature", "appguard=:" + Data(repeating: 0, count: 64).base64EncodedString() + ":")]
        let candidate = RequestInput(method: input.method, target: input.target, headers: headers + wireSuffix, body: input.body)
        _ = try RequestProfile.validatedHeaders(candidate)
        try RequestProfile.validateParameters(parameters)
        try RequestProfile.validateTime(parameters, now: RequestProfile.clock(now))
        headers[1] = HTTPHeader("Content-Digest", "sha-256=:" + Data(SHA256.hash(data: candidate.body)).base64EncodedString() + ":")
        let request = RequestInput(method: candidate.method, target: candidate.target, headers: headers, body: candidate.body)
        let base = try RequestProfile.signatureBase(request, parameters: parameters, origin: origin)
        let signature: Data
        do { signature = try key.sign(signatureBase: base) }
        catch { throw AppGuardError.signingFailed }
        _ = try P256WireSignature.der(fromRaw: signature)
        headers += [wireSuffix[0], HTTPHeader("Signature", "appguard=:" + signature.base64EncodedString() + ":")]
        return SignedRequest(request: RequestInput(method: request.method, target: request.target, headers: headers, body: request.body),
            parameters: parameters, signature: Data(Array(signature)), signatureBase: base)
    }
}

extension SignatureParameters {
    var serialized: String {
        "(\"@method\" \"@target-uri\" \"content-type\" \"content-digest\" \"authorization\" \"appguard-app-id\");created=\(created);expires=\(expires);nonce=\"\(nonce)\";keyid=\"\(keyID)\";alg=\"\(algorithm)\";tag=\"\(tag)\""
    }
}

/// Restricted request-v0 canonicalization, useful for fixture conformance. This is not a server verifier.
public enum RequestProfile {
    static let maxTimestamp: Int64 = 999_999_999_999_999
    static let token = "[!#$%&'*+.^_`|~0-9A-Za-z-]+"
    static let singletons: Set<String> = ["content-type", "content-digest", "authorization", "appguard-app-id", "content-encoding",
        "signature-input", "signature", "content-length", "transfer-encoding", "host"]
    static func matches(_ value: String, _ pattern: String) -> Bool {
        value.range(of: "\\A(?:" + pattern + ")\\z", options: .regularExpression) != nil
    }
    static func identifier(_ value: String) throws {
        guard matches(value, "[A-Za-z0-9._:-]{1,128}") else { throw AppGuardError.invalidRequest }
    }
    static func clock(_ supplied: Int64?) throws -> Int64 {
        let value = supplied ?? Int64(Date().timeIntervalSince1970.rounded(.down))
        guard value >= 0, value <= maxTimestamp else { throw AppGuardError.invalidTime }
        return value
    }
    static func urlBase64(_ data: Data) -> String {
        data.base64EncodedString().replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }
    static func validateOrigin(_ origin: String) throws {
        guard origin.utf8.count <= 512, matches(origin, "https://[a-z0-9.-]+(?::[1-9][0-9]{0,4})?") else { throw AppGuardError.invalidRequest }
        let parts = String(origin.dropFirst(8)).split(separator: ":", omittingEmptySubsequences: false)
        let host = String(parts[0])
        guard host.count <= 253, host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ matches(String($0), "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?") }) else { throw AppGuardError.invalidRequest }
        if parts.count == 2 {
            guard let port = Int(parts[1]), port <= 65535, port != 443 else { throw AppGuardError.invalidRequest }
        }
    }
    static func decodePercent(_ value: String) throws -> [UInt8] {
        let bytes = Array(value.utf8)
        var result: [UInt8] = []; var index = 0
        func hex(_ byte: UInt8) -> UInt8? {
            switch byte { case 48...57: return byte - 48; case 65...70: return byte - 55; case 97...102: return byte - 87; default: return nil }
        }
        while index < bytes.count {
            if bytes[index] == 37 {
                guard index + 2 < bytes.count, let hi = hex(bytes[index + 1]), let lo = hex(bytes[index + 2]) else { throw AppGuardError.invalidRequest }
                result.append(hi * 16 + lo); index += 3
            } else { result.append(bytes[index]); index += 1 }
        }
        return result
    }
    static func validateTarget(_ target: String) throws {
        guard target.utf8.count <= 8192, !target.hasPrefix("//"), matches(target, "/[A-Za-z0-9._~!$&'()*+,;=:@/?%\\-]*") else { throw AppGuardError.invalidRequest }
        let decoded = try decodePercent(target)
        guard !decoded.contains(where: { $0 < 32 || $0 == 127 || $0 == 92 }) else { throw AppGuardError.invalidRequest }
        let path = try decodePercent(String(target.split(separator: "?", maxSplits: 1, omittingEmptySubsequences: false)[0]))
        guard !path.split(separator: 47, omittingEmptySubsequences: false).contains(where: { Array($0) == [46] || Array($0) == [46, 46] }) else { throw AppGuardError.invalidRequest }
    }
    static func validatedHeaders(_ request: RequestInput) throws -> [String: String] {
        guard request.body.count <= 1_048_576, request.headers.count <= 64,
              request.method.utf8.count <= 32, request.method == request.method.uppercased(), matches(request.method, token) else { throw AppGuardError.invalidRequest }
        try validateTarget(request.target)
        var result: [String: String] = [:]; var size = 0
        for header in request.headers {
            size += header.name.utf8.count + header.value.utf8.count
            guard size <= 16384, matches(header.name, token),
                  header.value.utf8.allSatisfy({ 32...126 ~= $0 }), !header.value.hasPrefix(" "), !header.value.hasSuffix(" ") else { throw AppGuardError.invalidRequest }
            let name = header.name.lowercased()
            guard !singletons.contains(name) || result[name] == nil else { throw AppGuardError.invalidRequest }
            result[name] = header.value
        }
        guard let type = result["content-type"], !type.isEmpty, let digest = result["content-digest"],
              let authorization = result["authorization"], let appID = result["appguard-app-id"],
              matches(authorization, "(?i:Bearer) [A-Za-z0-9._~+/-]+=*"),
              result["content-encoding", default: "identity"] == "identity" else { throw AppGuardError.invalidRequest }
        try identifier(appID)
        guard matches(digest, "sha-256=:[A-Za-z0-9+/]{43}=:") else { throw AppGuardError.invalidRequest }
        let encoded = String(digest.dropFirst(9).dropLast())
        guard let raw = Data(base64Encoded: encoded), raw.count == 32, raw.base64EncodedString() == encoded else { throw AppGuardError.invalidRequest }
        if let length = result["content-length"] {
            guard length == String(request.body.count), result["transfer-encoding"] == nil else { throw AppGuardError.invalidRequest }
        }
        if let transfer = result["transfer-encoding"], transfer != "chunked" { throw AppGuardError.invalidRequest }
        return result
    }
    static func validateParameters(_ parameters: SignatureParameters) throws {
        guard parameters.algorithm == "ecdsa-p256-sha256", parameters.tag == "appguard-request-v0" else { throw AppGuardError.unsupportedProfile }
        try identifier(parameters.keyID)
        guard matches(parameters.nonce, "[A-Za-z0-9_-]{22}"),
              let raw = Data(base64Encoded: parameters.nonce.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "=="),
              raw.count == 16, urlBase64(raw) == parameters.nonce else { throw AppGuardError.invalidRequest }
        guard parameters.created >= 0, parameters.created <= maxTimestamp, parameters.expires >= 0, parameters.expires <= maxTimestamp else { throw AppGuardError.invalidTime }
    }
    static func validateTime(_ p: SignatureParameters, now: Int64) throws {
        guard p.created < p.expires, p.expires - p.created <= 120, p.created <= now + 30, now < p.expires else { throw AppGuardError.invalidTime }
    }
    public static func signatureBase(_ request: RequestInput, parameters: SignatureParameters, origin: String) throws -> Data {
        let headers = try validatedHeaders(request)
        try validateOrigin(origin); try validateParameters(parameters)
        let lines = ["\"@method\": " + request.method, "\"@target-uri\": " + origin + request.target] +
            ["content-type", "content-digest", "authorization", "appguard-app-id"].map { "\"" + $0 + "\": " + headers[$0]! } +
            ["\"@signature-params\": " + parameters.serialized]
        return Data(lines.joined(separator: "\n").utf8)
    }
}
