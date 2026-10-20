import Foundation
// No keychain calls: this test double isolates only C ABI input/output ownership.
public struct NativeBridge { public init() {}
public func invoke(operation: String, payload: String) -> String { return payload == "oversize-result" ? String(repeating:"a",count:4097) : "{\"ok\":true,\"result\":{}}" } }
@main struct OwnershipTests {
 static func main() {
  for _ in 0..<10000 {
   let response = "publicKey".withCString { op in "{}".withCString { payload in appGuardUnityInvoke(op,payload) } }
   precondition(response != nil, "owned response required")
   precondition(String(cString:response!) == "{\"ok\":true,\"result\":{}}")
   appGuardUnityFree(response)
  }
  let invalid = appGuardUnityInvoke(nil,nil)!; precondition(String(cString:invalid).contains("APPGUARD_INVALID_INPUT")); appGuardUnityFree(invalid)
  for size in [1500001,1500002] { let invalid=String(repeating:"a",count:size).withCString { payload in "prepare".withCString { op in appGuardUnityInvoke(op,payload)! } }; precondition(String(cString:invalid).contains("APPGUARD_INVALID_INPUT")); appGuardUnityFree(invalid) }
  let invalidUTF8:[CChar] = [-1,0]; let invalidEncoding=invalidUTF8.withUnsafeBufferPointer { payload in "prepare".withCString { op in appGuardUnityInvoke(op,payload.baseAddress)! } }; precondition(String(cString:invalidEncoding).contains("APPGUARD_INVALID_INPUT")); appGuardUnityFree(invalidEncoding)
  for size in [8193,8194] {
   let response=String(repeating:"a",count:size).withCString { payload in "scanLocalRisk".withCString { op in appGuardUnityInvoke(op,payload)! } }
   precondition(String(cString:response).contains("APPGUARD_INVALID_INPUT"),"scan input limit");appGuardUnityFree(response)
  }
  let oversized="scanLocalRisk".withCString { op in "oversize-result".withCString { payload in appGuardUnityInvoke(op,payload)! } }
  precondition(String(cString:oversized).contains("APPGUARD_OPERATION_FAILED"),"scan output limit");appGuardUnityFree(oversized)
  appGuardUnityFree(nil)
  print("10000 owned invoke/free cycles plus null, oversize and invalid UTF8 checks passed")
 }
}
