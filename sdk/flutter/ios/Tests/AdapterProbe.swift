import Foundation
import Flutter
// Deliberately excludes real probing/key APIs; only adapter dispatch is under test.
final class NativeBridge {
    static var calls = 0
    static var response = "native-response"
    func invoke(operation: String, payload: String) -> String {
        precondition(!Thread.isMainThread, "Native I/O reached main thread")
        precondition(operation == "scanLocalRisk" || operation == "prepare")
        NativeBridge.calls += 1
        return NativeBridge.response
    }
}
final class Queue: NSObject, FlutterTaskQueue {}
final class Messenger: NSObject, FlutterBinaryMessenger {
    let queue = Queue()
    func makeBackgroundTaskQueue() -> FlutterTaskQueue { queue }
}
final class UnsupportedMessenger: NSObject, FlutterBinaryMessenger {}
final class Registrar: FlutterPluginRegistrar {
    let binaryMessenger: FlutterBinaryMessenger
    var plugin: FlutterPlugin!
    var channel: FlutterMethodChannel!
    var published: Any?
    init(_ messenger: FlutterBinaryMessenger) { binaryMessenger = messenger }
    func messenger() -> FlutterBinaryMessenger { binaryMessenger }
    func addMethodCallDelegate(_ delegate: FlutterPlugin, channel: FlutterMethodChannel) {
        plugin = delegate; self.channel = channel
        channel.setMethodCallHandler(delegate.handle)
    }
    func publish(_ value: Any) { published = value }
}
@main struct AdapterProbe {
    static var assertions = 0
    static func equal(_ actual: String?, _ expected: String) {
        assertions += 1; precondition(actual == expected, "Adapter mismatch")
    }
    static func invoke(_ registrar: Registrar, _ payload: String, operation: String = "scanLocalRisk") -> String? {
        var answer: String?
        let semaphore = DispatchSemaphore(value: 0)
        DispatchQueue.global().async {
            registrar.plugin.handle(FlutterMethodCall(method: "invoke", arguments: ["operation": operation, "payload": payload])) {
                answer = $0 as? String; semaphore.signal()
            }
        }
        while semaphore.wait(timeout: .now()) != .success { RunLoop.current.run(until: Date(timeIntervalSinceNow: 0.001)) }
        return answer
    }
    static func main() {
        let registrar = Registrar(Messenger()); AppGuardPlugin.register(with: registrar)
        precondition(registrar.channel.queue != nil && registrar.published != nil)
        equal(invoke(registrar, "{}"), "native-response")
        equal(invoke(registrar, String(repeating: "x", count: 8193)), "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_INVALID_INPUT\"}}")
        equal(invoke(registrar, String(repeating: "é", count: 4097)), "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_INVALID_INPUT\"}}")
        precondition(NativeBridge.calls == 1)
        NativeBridge.response = String(repeating: "x", count: 4096)
        equal(invoke(registrar, String(repeating: "x", count: 8192)), NativeBridge.response)
        NativeBridge.response = String(repeating: "é", count: 2049)
        equal(invoke(registrar, "{}"), "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_OPERATION_FAILED\"}}")
        NativeBridge.response = String(repeating: "x", count: 9000)
        equal(invoke(registrar, "{}", operation: "prepare"), NativeBridge.response)
        (registrar.plugin as! AppGuardPlugin).detachFromEngine(for: registrar)
        precondition(registrar.channel.handler == nil)
        let calls = NativeBridge.calls
        equal(invoke(registrar, "{}"), "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_NATIVE_UNAVAILABLE\"}}")
        let unsupported = Registrar(UnsupportedMessenger()); AppGuardPlugin.register(with: unsupported)
        precondition(unsupported.channel.queue == nil)
        equal(invoke(unsupported, "{}"), "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_NATIVE_UNAVAILABLE\"}}")
        precondition(NativeBridge.calls == calls)
        print("Swift AdapterProbe: \(assertions) results plus queue/lifecycle/thread checks passed")
    }
}
