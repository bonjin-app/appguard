#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
FLUTTER_ROOT="${FLUTTER_ROOT:-$PWD/.tools/flutter}"
: "${ANDROID_HOME:?Set ANDROID_HOME to Android SDK}"
EVIDENCE="$PWD/.evidence/risk-bridge"
mkdir -p "$EVIDENCE/java" "$EVIDENCE/swift-host" "$EVIDENCE/module-cache" "$EVIDENCE/tmp" "$EVIDENCE/cocoapods"
export TMPDIR="$EVIDENCE/tmp" CP_HOME_DIR="$EVIDENCE/cocoapods" COCOAPODS_DISABLE_STATS=true
FLUTTER_SUPPRESS_ANALYTICS=true "$FLUTTER_ROOT/bin/flutter" test > "$EVIDENCE/dart-green.log" 2>&1
FLUTTER_SUPPRESS_ANALYTICS=true "$FLUTTER_ROOT/bin/flutter" analyze > "$EVIDENCE/analyze.log" 2>&1
python3 tool/pack.py --output "$EVIDENCE/appguard_flutter.tar.gz" > "$EVIDENCE/package.log" 2>&1
python3 tool/verify_package.py --archive "$EVIDENCE/appguard_flutter.tar.gz" >> "$EVIDENCE/package.log" 2>&1
CP="$FLUTTER_ROOT/bin/cache/artifacts/engine/android-arm64/flutter.jar:$ANDROID_HOME/platforms/android-36/android.jar"
javac --release 11 -cp "$CP" -d "$EVIDENCE/java" $(find android/src/main/java android/src/test/java -name '*.java') > "$EVIDENCE/java-green.log" 2>&1
java -cp "$EVIDENCE/java:$CP" io.appguard.flutter.AdapterProbe >> "$EVIDENCE/java-green.log" 2>&1
xcrun swiftc -swift-version 5 -module-cache-path "$EVIDENCE/module-cache" -emit-library -emit-module -module-name Flutter ios/Tests/FlutterShim.swift -o "$EVIDENCE/swift-host/libFlutter.dylib" -emit-module-path "$EVIDENCE/swift-host/Flutter.swiftmodule" > "$EVIDENCE/swift-host.log" 2>&1
xcrun swiftc -swift-version 5 -module-cache-path "$EVIDENCE/module-cache" -I "$EVIDENCE/swift-host" -L "$EVIDENCE/swift-host" -lFlutter -Xlinker -rpath -Xlinker "$EVIDENCE/swift-host" ios/Classes/AppGuardPlugin.swift ios/Tests/AdapterProbe.swift -o "$EVIDENCE/swift-host/AdapterProbe" >> "$EVIDENCE/swift-host.log" 2>&1
"$EVIDENCE/swift-host/AdapterProbe" >> "$EVIDENCE/swift-host.log" 2>&1
xcrun swiftc -swift-version 5 -module-cache-path "$EVIDENCE/module-cache" -emit-library -emit-module -emit-module-path "$EVIDENCE/appguard_flutter.swiftmodule" -module-name appguard_flutter -target arm64-apple-ios15.0-simulator -sdk "$(xcrun --sdk iphonesimulator --show-sdk-path)" -F "$FLUTTER_ROOT/bin/cache/artifacts/engine/ios/Flutter.xcframework/ios-arm64_x86_64-simulator" -framework Flutter ios/Classes/Native/*.swift ios/Classes/AppGuardPlugin.swift -o "$EVIDENCE/libappguard_flutter.dylib" > "$EVIDENCE/swift-actual-framework.log" 2>&1
xcrun vtool -show-build "$EVIDENCE/libappguard_flutter.dylib" >> "$EVIDENCE/swift-actual-framework.log" 2>&1
mkdir -p "$EVIDENCE/relocated"
tar -xzf "$EVIDENCE/appguard_flutter.tar.gz" -C "$EVIDENCE/relocated"
"${RUBY:-ruby}" tool/verify_pods.rb "$EVIDENCE/relocated" > "$EVIDENCE/privacy-resource.log" 2>&1
shasum -a 256 "$EVIDENCE/appguard_flutter.tar.gz" "$EVIDENCE/libappguard_flutter.dylib" native-provenance.json > "$EVIDENCE/artifact-sha256.txt"
printf 'Flutter local risk bridge verification passed; receipts: %s\n' "$EVIDENCE"
