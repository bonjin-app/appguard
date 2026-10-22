#!/usr/bin/env bash
# Go/.NET/PHP verification; no service, installer, shell-eval or publication.
set -euo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
case "${1:-}" in
  '') [[ $# -eq 0 ]] || { echo 'Usage: test-extended-server-sdks.sh [--check]' >&2; exit 2; } ;;
  --check) [[ $# -eq 1 ]] || { echo 'Usage: test-extended-server-sdks.sh [--check]' >&2; exit 2; } ;;
  *) echo 'Usage: test-extended-server-sdks.sh [--check]' >&2; exit 2 ;;
esac

go_cmd="${APPGUARD_GO_CMD:-go}"
dotnet_cmd="${APPGUARD_DOTNET:-dotnet}"
php_cmd="${APPGUARD_PHP_CMD:-php}"
composer_phar="${APPGUARD_COMPOSER_PHAR:-$(command -v composer || true)}"
for runtime in "$go_cmd" "$dotnet_cmd" "$php_cmd"; do
  command -v "$runtime" >/dev/null || { echo "Required executable unavailable: $runtime" >&2; exit 127; }
done
[[ -f "$composer_phar" && -r "$composer_phar" ]] || { echo 'Set APPGUARD_COMPOSER_PHAR to a readable Composer PHAR/script file' >&2; exit 127; }
# Resolve file paths before changing SDK working directories. Each override is one
# executable/file path, never a shell command or string of command arguments.
go_cmd="$(command -v "$go_cmd")"
dotnet_cmd="$(command -v "$dotnet_cmd")"
php_cmd="$(command -v "$php_cmd")"
for name in go_cmd dotnet_cmd php_cmd composer_phar; do
  value="${!name}"
  [[ "$value" = /* ]] || printf -v "$name" '%s/%s' "$PWD" "$value"
done
state="$(mktemp -d "${TMPDIR:-/tmp}/appguard-extended.XXXXXX")"
trap 'rm -rf -- "$state"' EXIT
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_UI_LANGUAGE=en
export APPGUARD_DOTNET="$dotnet_cmd"
export APPGUARD_DOTNET_CLI_HOME="${APPGUARD_DOTNET_CLI_HOME:-$state/dotnet-home}"
export DOTNET_CLI_HOME="$APPGUARD_DOTNET_CLI_HOME"
export APPGUARD_NUGET_PACKAGES="${APPGUARD_NUGET_PACKAGES:-$root/sdk/dotnet/.tools/packages}"
export NUGET_PACKAGES="$APPGUARD_NUGET_PACKAGES"
export GOTOOLCHAIN=local
export GOPATH="${APPGUARD_GO_PATH:-$root/sdk/go/.tools/gopath}"
export GOCACHE="${APPGUARD_GO_CACHE:-$root/sdk/go/.tools/cache}"
export GOFLAGS=-mod=readonly
export GOWORK=off
export COMPOSER_HOME="$state/composer-home"
export COMPOSER_CACHE_DIR="$state/composer-cache"
export COMPOSER_DISABLE_NETWORK=1
export COMPOSER_NO_INTERACTION=1

"$go_cmd" version
(cd "$root/sdk/dotnet" && "$dotnet_cmd" --version)
"$php_cmd" -n --version
"$php_cmd" -n -r 'if (PHP_INT_SIZE !== 8 || !extension_loaded("openssl") || !extension_loaded("hash") || !extension_loaded("json")) { fwrite(STDERR, "64-bit PHP with OpenSSL/hash/JSON required without php.ini\n"); exit(1); }'
# Composer itself needs Phar and an encoding extension. Some distributions ship
# these as shared modules, while our SDK needs neither. Keep php.ini disabled
# and load only fixed module names from the selected runtime for Composer calls.
composer_php_args=(-n)
add_composer_extension() {
  local extension module_path
  for extension in "$@"; do
    module_path="$("$php_cmd" -n -r 'echo ini_get("extension_dir"), "/", $argv[1], ".", PHP_SHLIB_SUFFIX;' -- "$extension")"
    if [[ "$module_path" = /* && -f "$module_path" && -r "$module_path" ]]; then
      composer_php_args+=(-d "extension=$module_path")
      return
    fi
  done
  echo "Composer requires an installed $* module in an absolute PHP extension_dir" >&2
  exit 1
}
if ! "$php_cmd" -n -r 'exit(extension_loaded("phar") ? 0 : 1);'; then
  add_composer_extension phar
fi
if ! "$php_cmd" -n -r 'exit(extension_loaded("iconv") || extension_loaded("mbstring") ? 0 : 1);'; then
  add_composer_extension iconv mbstring
fi
"$php_cmd" "${composer_php_args[@]}" "$composer_phar" --version
[[ "${1:-}" != --check ]] || exit 0
(
  cd "$root/sdk/go"
  "$go_cmd" test -count=1 ./...
  "$go_cmd" test -race -count=1 ./...
  "$go_cmd" vet ./...
  "$go_cmd" build ./...
)
bash "$root/sdk/dotnet/scripts/verify.sh"
(
  cd "$root/sdk/php"
  "$php_cmd" "${composer_php_args[@]}" "$composer_phar" validate --strict --no-plugins
  "$php_cmd" "${composer_php_args[@]}" "$composer_phar" install --no-interaction --no-plugins --no-scripts --no-progress
  "$php_cmd" -n tests/run-all.php
)
