#!/usr/bin/env bash
# Full local verification. Redis must be a new disposable loopback instance.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root"
uv_cmd="${APPGUARD_UV_CMD:-uv}"
maven_cmd="${APPGUARD_MAVEN_CMD:-mvn}"
export APPGUARD_REDIS_URL="${APPGUARD_TEST_REDIS_URL:?Set a disposable loopback APPGUARD_TEST_REDIS_URL}"

"$uv_cmd" sync --locked --project sdk/python
"$uv_cmd" run --frozen --project sdk/python python scripts/check_cross_sdk_replay.py --validate-url
"$uv_cmd" sync --locked --project reference/python
"$uv_cmd" run --frozen --project reference/python pytest reference/python/tests -q
"$uv_cmd" run --frozen --project sdk/python pytest sdk/python/tests -q
"$uv_cmd" build --project sdk/python
npm --prefix sdk/node ci --ignore-scripts
npm --prefix sdk/node test
npm --prefix sdk/node run test:types
npm --prefix sdk/node run test:install
"$maven_cmd" -B -f sdk/spring-boot/pom.xml package
"$maven_cmd" -B -f sdk/spring-boot/pom.xml org.apache.maven.plugins:maven-dependency-plugin:3.8.1:build-classpath \
  -Dmdep.outputFile=target/test-classpath.txt -Dmdep.includeScope=test
"$uv_cmd" run --frozen --project sdk/python python scripts/check_cross_sdk_replay.py
