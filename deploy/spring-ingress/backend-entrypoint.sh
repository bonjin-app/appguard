#!/bin/sh
set -eu
# Password files are explicit narrow read-only mounts. Never print their values.
APPGUARD_BACKEND_KEYSTORE_PASSWORD=$(cat /run/secrets/backend-password)
APPGUARD_BACKEND_TRUSTSTORE_PASSWORD=$APPGUARD_BACKEND_KEYSTORE_PASSWORD
export APPGUARD_BACKEND_KEYSTORE_PASSWORD APPGUARD_BACKEND_TRUSTSTORE_PASSWORD
exec java -cp '/opt/appguard/backend.jar:/opt/appguard/lib/*' io.appguard.example.BackendMain
