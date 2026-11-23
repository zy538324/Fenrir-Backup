#!/bin/sh
# Start a throw-away MinIO on 127.0.0.1:$1 for the S3 tests (FENRIR_TEST_S3).
# MINIO is the server binary; credentials come from MINIO_ROOT_USER/PASSWORD.
dir=$(mktemp -d)
exec "${MINIO:-minio}" server --quiet --address "127.0.0.1:$1" "$dir"
