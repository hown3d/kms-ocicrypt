#!/usr/bin/env sh
#
OCICRYPT_KEYPROVIDER_CONFIG=$(pwd)/test/ocicrypt.json skopeo --override-os=linux --debug copy --encryption-key provider:kms-crypt:139845b9-fb6f-43e0-a6f3-8134496e4823 docker://nginx docker://ttl.sh/imgcrypt-test
