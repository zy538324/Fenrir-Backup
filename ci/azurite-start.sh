#!/bin/sh
# Start a throw-away Azurite (Azure Storage emulator, MIT) with the blob service on 127.0.0.1:$1 for the Azure
# tests (FENRIR_TEST_AZURE). AZURITE is the azurite-blob command (npm install azurite).
dir=$(mktemp -d)
exec "${AZURITE:-azurite-blob}" --silent --skipApiVersionCheck --blobHost 127.0.0.1 --blobPort "$1" --location "$dir"
