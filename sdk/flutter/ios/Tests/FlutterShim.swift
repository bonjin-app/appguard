// Host-only protocol double. Final compilation also uses the actual Flutter framework.
import Foundation
@objc public protocol FlutterTaskQueue {}
@objc public protocol FlutterBinaryMessenger {
    @objc optional func makeBackgroundTaskQueue() -> FlutterTaskQueue
}
public typealias FlutterResult = (Any?) -> Void
public let FlutterMethodNotImplemented = NSObject()
public final class FlutterMethodCall {
    public let method: String
    public let arguments: Any?
    public init(method: String, arguments: Any?) { self.method = method; self.arguments = arguments }
}
public final class FlutterStandardMethodCodec {
    public static func sharedInstance() -> FlutterStandardMethodCodec { FlutterStandardMethodCodec() }
}
public protocol FlutterPlugin {
    static func register(with registrar: FlutterPluginRegistrar)
    func handle(_ call: FlutterMethodCall, result: @escaping FlutterResult)
}
public protocol FlutterPluginRegistrar {
    func messenger() -> FlutterBinaryMessenger
    func addMethodCallDelegate(_ delegate: FlutterPlugin, channel: FlutterMethodChannel)
    func publish(_ value: Any)
}
public final class FlutterMethodChannel {
    public let queue: FlutterTaskQueue?
    public var handler: ((FlutterMethodCall, @escaping FlutterResult) -> Void)?
    public init(name: String, binaryMessenger: FlutterBinaryMessenger) { queue = nil }
    public init(name: String, binaryMessenger: FlutterBinaryMessenger, codec: FlutterStandardMethodCodec, taskQueue: FlutterTaskQueue?) { queue = taskQueue }
    public func setMethodCallHandler(_ handler: ((FlutterMethodCall, @escaping FlutterResult) -> Void)?) { self.handler = handler }
}
