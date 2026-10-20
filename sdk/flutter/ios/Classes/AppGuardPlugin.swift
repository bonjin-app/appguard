import Flutter
import Foundation
// Staged AppGuardApple sources are compiled into this pod's module.
public final class AppGuardPlugin: NSObject, FlutterPlugin {
    private let bridge = NativeBridge()
    public static func register(with registrar: FlutterPluginRegistrar) {
        let channel = FlutterMethodChannel(name: "io.appguard/client", binaryMessenger: registrar.messenger())
        registrar.addMethodCallDelegate(AppGuardPlugin(), channel: channel)
    }
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard call.method == "invoke" else { result(FlutterMethodNotImplemented); return }
        guard let arguments = call.arguments as? [String: Any], arguments.count == 2,
              let operation = arguments["operation"] as? String,
              let payload = arguments["payload"] as? String,
              payload.utf8.count <= 1500000 else {
            result("{\"ok\":false,\"error\":{\"code\":\"APPGUARD_INVALID_INPUT\"}}")
            return
        }
        result(bridge.invoke(operation: operation, payload: payload))
    }
}
