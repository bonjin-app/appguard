import Foundation
import Security
import CryptoKit
import LocalAuthentication

public enum InstallationKeyError: Error, Equatable {
    case invalidApplicationTag, ambiguousApplicationTag, invalidExistingKey, secureEnclaveRequired, secureEnclaveUnavailable
    case storeFailure(Int32), publicKeyUnavailable, signingFailed
}
public enum InstallationKeyBacking: String { case keychain, secureEnclave }

// Internal seam replaces only persistent I/O in host tests. It does not export a private key.
protocol InstallationKeyStore {
    func lookup(tag: Data) throws -> [SecKey]
    func create(tag: Data, secureEnclaveRequired: Bool) throws -> SecKey
}

/// A persistent, installation-specific P-256 Security key. No private export or implicit rotation API.
public final class InstallationKey: RequestSigningKey {
    public let backing: InstallationKeyBacking
    private let key: SecKey
    private static let lock = NSLock()

    /// The application owns its tag namespace and enrollment lifecycle. Existing unusable keys fail closed.
    public static func getOrCreate(applicationTag: String, secureEnclaveRequired: Bool = false) throws -> InstallationKey {
        try loadOrCreate(applicationTag: applicationTag, secureEnclaveRequired: secureEnclaveRequired, store: SecurityKeyStore())
    }
    static func loadOrCreate(applicationTag: String, secureEnclaveRequired: Bool, store: any InstallationKeyStore) throws -> InstallationKey {
        let tag = Data(applicationTag.utf8)
        guard (1...256).contains(tag.count), !applicationTag.unicodeScalars.contains(where: { $0.value < 32 || $0.value == 127 }) else {
            throw InstallationKeyError.invalidApplicationTag
        }
        lock.lock(); defer { lock.unlock() }
        let existing = try store.lookup(tag: tag)
        if !existing.isEmpty { return try checked(existing, secureEnclaveRequired: secureEnclaveRequired) }
        let created: SecKey
        do { created = try store.create(tag: tag, secureEnclaveRequired: secureEnclaveRequired) }
        catch InstallationKeyError.storeFailure(errSecDuplicateItem) {
            // Re-read a reported duplicate instead of deleting/overwriting it.
            // This is not cross-process arbitration for a shared tag.
            return try checked(store.lookup(tag: tag), secureEnclaveRequired: secureEnclaveRequired)
        }
        let result = try checked([created], secureEnclaveRequired: secureEnclaveRequired)
        let persisted = try checked(store.lookup(tag: tag), secureEnclaveRequired: secureEnclaveRequired)
        guard try result.publicKeyPEM() == persisted.publicKeyPEM() else { throw InstallationKeyError.ambiguousApplicationTag }
        return persisted
    }
    private static func checked(_ keys: [SecKey], secureEnclaveRequired: Bool) throws -> InstallationKey {
        guard keys.count == 1 else { throw InstallationKeyError.ambiguousApplicationTag }
        let key = keys[0]
        guard let attrs = SecKeyCopyAttributes(key) as? [String: Any],
              attrs[kSecAttrKeyType as String] as? String == kSecAttrKeyTypeECSECPrimeRandom as String,
              attrs[kSecAttrKeyClass as String] as? String == kSecAttrKeyClassPrivate as String,
              (attrs[kSecAttrKeySizeInBits as String] as? NSNumber)?.intValue == 256,
              SecKeyIsAlgorithmSupported(key, .sign, .ecdsaSignatureMessageX962SHA256) else { throw InstallationKeyError.invalidExistingKey }
        let backing: InstallationKeyBacking = attrs[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String ? .secureEnclave : .keychain
        guard !secureEnclaveRequired || backing == .secureEnclave else { throw InstallationKeyError.secureEnclaveRequired }
        let result = InstallationKey(key: key, backing: backing)
        _ = try result.publicKeyPEM() // Reject malformed/wrong-curve public representations without replacing the alias.
        return result
    }
    private init(key: SecKey, backing: InstallationKeyBacking) { self.key = key; self.backing = backing }
    public func publicKeyPEM() throws -> String {
        guard let publicKey = SecKeyCopyPublicKey(key) else { throw InstallationKeyError.publicKeyUnavailable }
        var error: Unmanaged<CFError>?
        guard let bytes = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
            _ = error?.takeRetainedValue(); throw InstallationKeyError.publicKeyUnavailable
        }
        do { return try P256.Signing.PublicKey(x963Representation: bytes).pemRepresentation }
        catch { throw InstallationKeyError.publicKeyUnavailable }
    }
    public func sign(signatureBase: Data) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, signatureBase as CFData, &error) as Data? else {
            _ = error?.takeRetainedValue(); throw InstallationKeyError.signingFailed
        }
        return try P256WireSignature.raw(fromDER: der)
    }
}

struct SecurityKeyStore: InstallationKeyStore {
    private let copyMatching: (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus
    init(copyMatching: @escaping (CFDictionary, UnsafeMutablePointer<CFTypeRef?>?) -> OSStatus = SecItemCopyMatching) {
        self.copyMatching = copyMatching
    }
    func lookup(tag: Data) throws -> [SecKey] {
        // Do not filter by curve/class: a conflicting item must be detected, never treated as a free alias.
        let authentication = LAContext()
        authentication.interactionNotAllowed = true
        var query: [String: Any] = [kSecClass as String: kSecClassKey, kSecAttrApplicationTag as String: tag,
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecMatchLimit as String: kSecMatchLimitAll, kSecReturnRef as String: true,
            kSecReturnAttributes as String: true,
            kSecUseAuthenticationContext as String: authentication]
        #if os(macOS)
        query[kSecUseDataProtectionKeychain as String] = true
        #endif
        var result: CFTypeRef?
        let status = copyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw InstallationKeyError.storeFailure(status) }
        guard let records = result as? [[String: Any]] else { throw InstallationKeyError.invalidExistingKey }
        return try records.map { record in
            // Synced or missing-metadata entries are not an empty tag and must
            // never trigger creation of another installation identity.
            guard let synchronized = record[kSecAttrSynchronizable as String] as? Bool, !synchronized,
                  let reference = record[kSecValueRef as String],
                  CFGetTypeID(reference as CFTypeRef) == SecKeyGetTypeID() else {
                throw InstallationKeyError.invalidExistingKey
            }
            return reference as! SecKey
        }
    }
    func create(tag: Data, secureEnclaveRequired: Bool) throws -> SecKey {
        guard !secureEnclaveRequired || SecureEnclave.isAvailable else { throw InstallationKeyError.secureEnclaveUnavailable }
        var privateAttributes: [String: Any] = [kSecAttrIsPermanent as String: true, kSecAttrApplicationTag as String: tag]
        #if os(macOS)
        // Request this macOS attribute without claiming software enforcement.
        privateAttributes[kSecAttrIsExtractable as String] = false
        #endif
        if secureEnclaveRequired {
            var accessError: Unmanaged<CFError>?
            guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .privateKeyUsage, &accessError) else {
                _ = accessError?.takeRetainedValue(); throw InstallationKeyError.secureEnclaveUnavailable
            }
            privateAttributes[kSecAttrAccessControl as String] = control
        } else {
            privateAttributes[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        var attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256, kSecPrivateKeyAttrs as String: privateAttributes]
        #if os(macOS)
        attrs[kSecUseDataProtectionKeychain as String] = true
        #endif
        if secureEnclaveRequired { attrs[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave }
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            let code = error.map { CFErrorGetCode($0.takeRetainedValue()) } ?? Int(errSecInternalComponent)
            throw InstallationKeyError.storeFailure(Int32(clamping: code))
        }
        return key
    }
}
