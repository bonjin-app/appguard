import Foundation

/// Strict DER / RFC 9421 r||s conversion. Private key material never passes through this API.
public enum P256WireSignature {
    private static let order: [UInt8] = [0xff,0xff,0xff,0xff,0x00,0x00,0x00,0x00,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        0xbc,0xe6,0xfa,0xad,0xa7,0x17,0x9e,0x84,0xf3,0xb9,0xca,0xc2,0xfc,0x63,0x25,0x51]
    private static func validScalar(_ scalar: [UInt8]) -> Bool {
        scalar.count == 32 && scalar.contains(where: { $0 != 0 }) && scalar.lexicographicallyPrecedes(order)
    }
    public static func der(fromRaw raw: Data) throws -> Data {
        let bytes = Array(raw)
        guard bytes.count == 64, validScalar(Array(bytes[0..<32])), validScalar(Array(bytes[32..<64])) else { throw AppGuardError.invalidSignature }
        func integer(_ scalar: ArraySlice<UInt8>) -> [UInt8] {
            var value = Array(scalar.drop(while: { $0 == 0 }))
            if value[0] >= 0x80 { value.insert(0, at: 0) }
            return [0x02, UInt8(value.count)] + value
        }
        let payload = integer(bytes[0..<32]) + integer(bytes[32..<64])
        return Data([0x30, UInt8(payload.count)] + payload)
    }
    public static func raw(fromDER der: Data) throws -> Data {
        let bytes = Array(der)
        guard (8...72).contains(bytes.count), bytes[0] == 0x30, bytes[1] == UInt8(bytes.count - 2) else { throw AppGuardError.invalidSignature }
        var index = 2
        func integer() throws -> [UInt8] {
            guard index + 2 <= bytes.count, bytes[index] == 0x02 else { throw AppGuardError.invalidSignature }
            let count = Int(bytes[index + 1]); index += 2
            guard (1...33).contains(count), index + count <= bytes.count else { throw AppGuardError.invalidSignature }
            var value = Array(bytes[index..<(index + count)]); index += count
            guard value[0] < 0x80 else { throw AppGuardError.invalidSignature }
            if value[0] == 0 {
                guard count > 1, value[1] >= 0x80 else { throw AppGuardError.invalidSignature }
                value.removeFirst()
            }
            guard value.count <= 32 else { throw AppGuardError.invalidSignature }
            let scalar = Array(repeating: UInt8(0), count: 32 - value.count) + value
            guard validScalar(scalar) else { throw AppGuardError.invalidSignature }
            return scalar
        }
        let raw = try integer() + integer()
        guard index == bytes.count else { throw AppGuardError.invalidSignature }
        return Data(raw)
    }
}
