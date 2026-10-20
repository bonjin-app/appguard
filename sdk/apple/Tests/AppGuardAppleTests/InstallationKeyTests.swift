import XCTest
import Security
import CryptoKit
@testable import AppGuardApple

final class InstallationKeyTests: XCTestCase {
    // The fake replaces only Keychain I/O; SecKey creation, validation and signing are real, nonpersistent operations.
    func testCreatesThenReusesSameEphemeralKeyWithoutPrivateExport() throws {
        let store = MemoryKeyStore()
        let first = try InstallationKey.loadOrCreate(applicationTag: "com.example.app.request-key", secureEnclaveRequired: false, store: store)
        let pem = try first.publicKeyPEM()
        let second = try InstallationKey.loadOrCreate(applicationTag: "com.example.app.request-key", secureEnclaveRequired: false, store: store)
        XCTAssertEqual(try second.publicKeyPEM(), pem)
        XCTAssertEqual(store.creates, 1)
        XCTAssertEqual(first.backing, .keychain)
        let base = Data("public test message".utf8)
        let raw = try second.sign(signatureBase: base)
        XCTAssertEqual(raw.count, 64)
        XCTAssertTrue(try P256.Signing.PublicKey(pemRepresentation: pem).isValidSignature(
            P256.Signing.ECDSASignature(rawRepresentation: raw), for: base))
    }

    func testExistingWrongCurvePublicKeyOrAmbiguousAliasNeverGeneratesReplacement() throws {
        let ec = try ephemeralSecKey()
        let rsa = try ephemeralSecKey(type: kSecAttrKeyTypeRSA, bits: 2048)
        let publicOnly = SecKeyCopyPublicKey(ec)!
        for keys in [[rsa], [publicOnly], [ec, ec]] {
            let store = MemoryKeyStore(keys: keys)
            XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: "test.tag", secureEnclaveRequired: false, store: store))
            XCTAssertEqual(store.creates, 0)
            XCTAssertEqual(store.keys.count, keys.count)
        }
    }

    func testLookupGenerationAndReadbackFailuresDoNotDeleteOrReplaceKeys() throws {
        let lookupFailure = MemoryKeyStore(); lookupFailure.lookupError = InstallationKeyError.storeFailure(-50)
        XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: "test.tag", secureEnclaveRequired: false, store: lookupFailure))
        XCTAssertEqual(lookupFailure.creates, 0)
        let generationFailure = MemoryKeyStore(); generationFailure.createError = InstallationKeyError.storeFailure(-1)
        XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: "test.tag", secureEnclaveRequired: false, store: generationFailure))
        XCTAssertEqual(generationFailure.creates, 1)
        XCTAssertEqual(generationFailure.keys.count, 0)
        let readbackFailure = MemoryKeyStore(); readbackFailure.failReadback = true
        XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: "test.tag", secureEnclaveRequired: false, store: readbackFailure))
        XCTAssertEqual(readbackFailure.creates, 1)
        XCTAssertEqual(readbackFailure.keys.count, 1)
    }

    func testExplicitEnclaveRequirementDoesNotReuseOrFallBackToSoftware() throws {
        let existing = MemoryKeyStore(keys: [try ephemeralSecKey()])
        XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: "test.tag", secureEnclaveRequired: true, store: existing)) { error in
            XCTAssertEqual(error as? InstallationKeyError, .secureEnclaveRequired)
        }
        XCTAssertEqual(existing.creates, 0)
        let unsupported = MemoryKeyStore(); unsupported.createError = InstallationKeyError.secureEnclaveUnavailable
        XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: "test.tag", secureEnclaveRequired: true, store: unsupported))
        XCTAssertEqual(unsupported.requirements, [true])
        let liesAboutHardware = MemoryKeyStore()
        XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: "test.tag", secureEnclaveRequired: true, store: liesAboutHardware))
        XCTAssertEqual(liesAboutHardware.creates, 1)
    }

    func testInvalidTagRejectsBeforeStorageAccess() throws {
        let store = MemoryKeyStore()
        for tag in ["", "test\u{0}tag", String(repeating: "x", count: 257)] {
            XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: tag, secureEnclaveRequired: false, store: store))
        }
        XCTAssertEqual(store.lookups, 0)
        XCTAssertEqual(store.creates, 0)
    }

    func testSynchronizedAliasIsVisibleAndRejectedBeforeAnyCreation() throws {
        let key = try ephemeralSecKey()
        let system = SecurityKeyStore(copyMatching: { query, result in
            let query = query as NSDictionary
            // Mirror Security's documented filtering: omitting this attribute
            // hides synchronized items rather than proving the tag is vacant.
            guard query[kSecAttrSynchronizable] as? String == kSecAttrSynchronizableAny as String else {
                return errSecItemNotFound
            }
            if query[kSecReturnAttributes] as? Bool == true {
                result?.pointee = [[kSecValueRef as String: key, kSecAttrSynchronizable as String: true]] as CFArray
            } else {
                result?.pointee = [key] as CFArray
            }
            return errSecSuccess
        })
        let store = CreationSentinelStore(delegate: system)
        XCTAssertThrowsError(try InstallationKey.loadOrCreate(applicationTag: "test.sync-tag", secureEnclaveRequired: false, store: store)) { error in
            XCTAssertEqual(error as? InstallationKeyError, .invalidExistingKey)
        }
        XCTAssertEqual(store.creates, 0)
    }

    func testSystemLookupPreservesNonsynchronizedKeyReference() throws {
        let key = try ephemeralSecKey()
        let store = SecurityKeyStore(copyMatching: { query, result in
            let query = query as NSDictionary
            if query[kSecReturnAttributes] as? Bool == true {
                result?.pointee = [[kSecValueRef as String: key, kSecAttrSynchronizable as String: false]] as CFArray
            } else {
                result?.pointee = [key] as CFArray
            }
            return errSecSuccess
        })
        let found = try store.lookup(tag: Data("test.tag".utf8))
        XCTAssertEqual(found.count, 1)
        let actual = try XCTUnwrap(SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(found[0])!, nil))
        let expected = try XCTUnwrap(SecKeyCopyExternalRepresentation(SecKeyCopyPublicKey(key)!, nil))
        XCTAssertEqual(actual as Data, expected as Data)
    }
}

final class CreationSentinelStore: InstallationKeyStore {
    let delegate: any InstallationKeyStore
    var creates = 0
    init(delegate: any InstallationKeyStore) { self.delegate = delegate }
    func lookup(tag: Data) throws -> [SecKey] { try delegate.lookup(tag: tag) }
    func create(tag: Data, secureEnclaveRequired: Bool) throws -> SecKey {
        creates += 1
        throw InstallationKeyError.storeFailure(errSecInternalComponent)
    }
}

func ephemeralSecKey(type: CFString = kSecAttrKeyTypeECSECPrimeRandom, bits: Int = 256) throws -> SecKey {
    var error: Unmanaged<CFError>?
    let attrs: [String: Any] = [kSecAttrKeyType as String: type, kSecAttrKeySizeInBits as String: bits,
        kSecPrivateKeyAttrs as String: [kSecAttrIsPermanent as String: false]]
    guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else { throw error!.takeRetainedValue() as Error }
    return key
}
final class MemoryKeyStore: InstallationKeyStore {
    var keys: [SecKey]; var lookups = 0; var creates = 0; var requirements: [Bool] = []
    var lookupError: InstallationKeyError?; var createError: InstallationKeyError?; var failReadback = false
    init(keys: [SecKey] = []) { self.keys = keys }
    func lookup(tag: Data) throws -> [SecKey] {
        lookups += 1
        if let error = lookupError { throw error }
        if failReadback && creates > 0 { throw InstallationKeyError.storeFailure(-1) }
        return keys
    }
    func create(tag: Data, secureEnclaveRequired: Bool) throws -> SecKey {
        creates += 1; requirements.append(secureEnclaveRequired)
        if let error = createError { throw error }
        let key = try ephemeralSecKey(); keys.append(key); return key
    }
}
