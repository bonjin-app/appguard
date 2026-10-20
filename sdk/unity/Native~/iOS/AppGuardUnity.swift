import Foundation
#if canImport(AppGuardApple)
import AppGuardApple
#endif

// Every non-null result owns MaxBytes+1 readable bytes. The C# decoder may safely
// scan through the bound; only AppGuardUnityFree releases this allocator's buffer.
private let maxBytes = 1_500_000
private let invalid = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_INVALID_INPUT\"}}"
private let failed = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_OPERATION_FAILED\"}}"
private func owned(_ value: String) -> UnsafeMutablePointer<CChar>? {
    let bytes = Array(value.utf8)
    guard bytes.count <= maxBytes, let memory = calloc(maxBytes + 1, 1) else { return nil }
    let result = memory.assumingMemoryBound(to: CChar.self)
    bytes.withUnsafeBytes { source in if let address=source.baseAddress { memcpy(result,address,bytes.count) } }
    return result
}
private func boundedString(_ pointer: UnsafePointer<CChar>?, _ limit: Int) -> String? {
    guard let pointer=pointer else {return nil}
    let count=strnlen(pointer,limit+1)
    guard count<=limit else {return nil}
    return String(bytes:UnsafeRawBufferPointer(start:pointer,count:count),encoding:.utf8)
}
@_cdecl("AppGuardUnityInvoke")
public func appGuardUnityInvoke(_ operation: UnsafePointer<CChar>?, _ payload: UnsafePointer<CChar>?) -> UnsafeMutablePointer<CChar>? {
    guard let op=boundedString(operation,64), let input=boundedString(payload,maxBytes) else {return owned(invalid)}
    let response=NativeBridge().invoke(operation:op,payload:input)
    return owned(response.utf8.count<=maxBytes ? response : failed)
}
@_cdecl("AppGuardUnityFree")
public func appGuardUnityFree(_ response: UnsafeMutablePointer<CChar>?) { free(response) }
