import ExpoModulesCore
import AppGuardApple

public class AppGuardModule: Module {
  public func definition() -> ModuleDefinition {
    Name("AppGuard")
    AsyncFunction("invoke") { (operation: String, payload: String) -> String in
      NativeBridge().invoke(operation: operation, payload: payload)
    }
  }
}
