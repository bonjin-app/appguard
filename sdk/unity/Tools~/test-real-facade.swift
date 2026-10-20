import Foundation
@main struct FacadeIntegrationTests {
 static func main() {
  let cases=[("unknown","{}","APPGUARD_UNSUPPORTED"),("prepare","not-json","APPGUARD_INVALID_INPUT"),("publicKey","{\"alias\":\"\",\"hardwareRequirement\":\"any\"}","APPGUARD_INVALID_INPUT"),("publicKey","{\"alias\":\"a\",\"hardwareRequirement\":\"strongbox\"}","APPGUARD_UNSUPPORTED")]
  for (op,payload,code) in cases {
   let response=op.withCString { op in payload.withCString { input in appGuardUnityInvoke(op,input)! } }
   let text=String(cString:response);appGuardUnityFree(response)
   precondition(text.contains(code),"fixed facade error mismatch")
  }
  print("4 real facade C ABI rejection cases passed; no persistent key operations")
 }
}
