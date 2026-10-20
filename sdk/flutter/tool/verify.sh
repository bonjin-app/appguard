#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
: "${JAVA_HOME:?Set JAVA_HOME to Java 17}"
: "${ANDROID_HOME:?Set ANDROID_HOME to Android SDK}"
FLUTTER_ROOT="${FLUTTER_ROOT:-$PWD/.tools/flutter}"
mkdir -p .evidence/java
python3 tool/pack.py
python3 tool/verify_package.py
FLUTTER_SUPPRESS_ANALYTICS=true "$FLUTTER_ROOT/bin/flutter" analyze
FLUTTER_SUPPRESS_ANALYTICS=true "$FLUTTER_ROOT/bin/flutter" test
"$JAVA_HOME/bin/javac" -cp "$FLUTTER_ROOT/bin/cache/artifacts/engine/android-arm64/flutter.jar:$ANDROID_HOME/platforms/android-36/android.jar" -d .evidence/java $(find android/src/main/java android/src/test/java -name '*.java')
"$JAVA_HOME/bin/java" -cp ".evidence/java:$FLUTTER_ROOT/bin/cache/artifacts/engine/android-arm64/flutter.jar:$ANDROID_HOME/platforms/android-36/android.jar" io.appguard.flutter.AdapterProbe
if command -v xcrun >/dev/null 2>&1; then
  xcrun swiftc -emit-library -emit-module -module-name appguard_flutter -target arm64-apple-ios15.0-simulator -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" -F "$FLUTTER_ROOT/bin/cache/artifacts/engine/ios/Flutter.xcframework/ios-arm64_x86_64-simulator" -framework Flutter ios/Classes/Native/*.swift ios/Classes/AppGuardPlugin.swift -o .evidence/libappguard_flutter.dylib
  xcrun vtool -show-build .evidence/libappguard_flutter.dylib
fi
