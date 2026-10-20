#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p .tools .evidence
xcrun swiftc -sanitize=address Native~/iOS/AppGuardUnity.swift Tools~/test-ownership.swift -o .tools/ownership
.tools/ownership > .evidence/native-asan.log 2>&1
xcrun swiftc Native~/iOS/AppGuardUnity.swift Tools~/test-ownership.swift -o .tools/ownership-leaks
MallocStackLogging=1 leaks --atExit -- .tools/ownership-leaks > .evidence/native-leaks.log 2>&1
cat .evidence/native-asan.log
tail -4 .evidence/native-leaks.log
