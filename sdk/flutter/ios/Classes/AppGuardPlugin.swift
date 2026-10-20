import Flutter
import Foundation
// Staged AppGuardApple sources are compiled into this pod's module.
public final class AppGuardPlugin: NSObject, FlutterPlugin {
    private let bridge = NativeBridge()
    private let lock = NSLock()
    private var active = true
    private var backgroundQueueAvailable = false
    private var channel: FlutterMethodChannel?
    private static let unavailable = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_NATIVE_UNAVAILABLE\"}}"
    private static let invalid = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_INVALID_INPUT\"}}"
    private static let failed = "{\"ok\":false,\"error\":{\"code\":\"APPGUARD_OPERATION_FAILED\"}}"

    public static func register(with registrar: FlutterPluginRegistrar) {
        let messenger = registrar.messenger()
        let queue = messenger.makeBackgroundTaskQueue?()
        let instance = AppGuardPlugin()
        instance.backgroundQueueAvailable = queue != nil
        let channel = queue == nil
            ? FlutterMethodChannel(name: "io.appguard/client", binaryMessenger: messenger)
            : FlutterMethodChannel(name: "io.appguard/client", binaryMessenger: messenger,
                codec: FlutterStandardMethodCodec.sharedInstance(), taskQueue: queue)
        instance.channel = channel
        registrar.addMethodCallDelegate(instance, channel: channel)
        // Publication enables Flutter's documented engine-detach callback.
        registrar.publish(instance)
    }
    public func detachFromEngine(for registrar: FlutterPluginRegistrar) {
        lock.lock(); active = false; lock.unlock()
        channel?.setMethodCallHandler(nil)
        channel = nil
    }
    public func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult) {
        guard call.method == "invoke" else { result(FlutterMethodNotImplemented); return }
        guard let arguments = call.arguments as? [String: Any], arguments.count == 2,
              let operation = arguments["operation"] as? String,
              let payload = arguments["payload"] as? String,
              payload.utf8.count <= (operation == "scanLocalRisk" ? 8192 : 1500000) else {
            result(Self.invalid)
            return
        }
        lock.lock(); let available = active && backgroundQueueAvailable; lock.unlock()
        // Fail explicitly on engines without queues; never probe on their UI handler.
        guard available else { result(Self.unavailable); return }
        let response = bridge.invoke(operation: operation, payload: payload)
        result(operation == "scanLocalRisk" && response.utf8.count > 4096 ? Self.failed : response)
    }
}
