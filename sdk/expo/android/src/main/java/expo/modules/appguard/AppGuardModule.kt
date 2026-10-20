package expo.modules.appguard

import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition
import io.appguard.android.NativeBridge

class AppGuardModule : Module() {
  override fun definition() = ModuleDefinition {
    Name("AppGuard")
    AsyncFunction("invoke") { operation: String, payload: String ->
      try {
        val context = appContext.reactContext
        if (context == null) """{"ok":false,"error":{"code":"APPGUARD_NATIVE_UNAVAILABLE"}}"""
        else NativeBridge(context.applicationContext).invoke(operation, payload)
      } catch (_: Exception) {
        """{"ok":false,"error":{"code":"APPGUARD_OPERATION_FAILED"}}"""
      }
    }
  }
}
