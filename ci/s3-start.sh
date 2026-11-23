#!/bin/sh
# Start a throw-away S3 emulator with Object Lock (moto) on 127.0.0.1:$1 for the S3 tests
# (FENRIR_TEST_S3). MinIO no longer publishes its server binary or container image, so CI uses moto.
exec "${MOTO_SERVER:-moto_server}" -H 127.0.0.1 -p "$1"
