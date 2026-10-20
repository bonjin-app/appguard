#!/bin/sh
# Local debug signing for isolated tests only. Never uses the global debug keystore.
set -eu
cd "$(dirname "$0")/.."
umask 077
mkdir -p .tools
if [ -e .tools/appguard-test-debug.keystore ]; then
  exit 0
fi
keytool -genkeypair -keystore .tools/appguard-test-debug.keystore \
  -storetype PKCS12 -storepass android -keypass android \
  -alias androiddebugkey -keyalg RSA -keysize 2048 -validity 3650 \
  -dname 'CN=AppGuard Isolated Tests' -noprompt
