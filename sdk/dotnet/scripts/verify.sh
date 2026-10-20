#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
export DOTNET_GENERATE_ASPNET_CERTIFICATE=false
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
export DOTNET_CLI_UI_LANGUAGE=en
export DOTNET_CLI_HOME="${APPGUARD_DOTNET_CLI_HOME:-$PWD/.tools/cli-home}"
export NUGET_PACKAGES="${APPGUARD_NUGET_PACKAGES:-$PWD/.tools/packages}"
dotnet_command="${APPGUARD_DOTNET:-dotnet}"
"$dotnet_command" restore AppGuard.slnx --locked-mode
"$dotnet_command" test AppGuard.slnx -c Release --no-restore
"$dotnet_command" build AppGuard.slnx -c Release --no-restore
"$dotnet_command" pack src/AppGuard/AppGuard.csproj -c Release --no-build --no-restore -o artifacts
