#!/bin/sh
# Compile only platform-neutral production classes and this test-only probe.
set -eu
cd "$(dirname "$0")/.."
mkdir -p .tools/probe-classes
javac --release 17 -d .tools/probe-classes \
  src/main/java/io/appguard/android/RequestSigner.java \
  src/main/java/io/appguard/android/EcdsaP256.java \
  src/main/java/io/appguard/android/JcaSigningKey.java \
  src/test/java/io/appguard/android/SignerProbe.java
exec java -cp .tools/probe-classes io.appguard.android.SignerProbe
