#!/usr/bin/env bash
# This file is Free Software under the Apache-2.0 License
# without warranty, see README.md and LICENSES/Apache-2.0.txt for details.
#
# SPDX-License-Identifier: Apache-2.0
#
# SPDX-FileCopyrightText: 2026 German Federal Office for Information Security (BSI) <https://www.bsi.bund.de>
# Software-Engineering: 2026 Intevation GmbH <https://intevation.de>

ENDPOINT="http://localhost:8888/api/v1/import"
DOCUMENT_URL="https://csaf-cms.example.com/api/documents/42"
SHA256=`sha256sum $1 | cut -f 1 -d ' '`
SHA512=`sha512sum $1 | cut -f 1 -d ' '`
echo SHA256: $SHA256
echo SHA512: $SHA512
# validation_status: valid, invalid, not_validated
validation_status=valid

curl -s -X POST \
    -F advisory=@$1 \
    -F validation_status=$validation_status \
    -F document_url=$DOCUMENT_URL \
    -F "hash-256"=$SHA256 \
    -F "hash-512"=$SHA512 \
    $ENDPOINT
