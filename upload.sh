#!/usr/bin/env bash

ENDPOINT="http://localhost:8888/api/v1/import"
SHA256=`sha256sum $1 | cut -f 1 -d ' '`
SHA512=`sha512sum $1 | cut -f 1 -d ' '`
echo SHA256: $SHA256
echo SHA512: $SHA512
# validation_status: valid, invalid, not_validated
validation_status=valid

curl -X POST \
    -F advisory=@$1 \
    -F validation_status=$validation_status \
    -F "hash-256"=$SHA256 \
    -F "hash-512"=$SHA512 \
    $ENDPOINT
