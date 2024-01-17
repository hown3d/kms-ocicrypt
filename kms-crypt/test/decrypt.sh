#!/usr/bin/env sh
#
OCICRYPT_KEYPROVIDER_CONFIG=$(pwd)/test/ocicrypt.json skopeo --override-os=linux copy --decryption-key provider:kms-crypt:139845b9-fb6f-43e0-a6f3-8134496e4823 docker://ttl.sh/imgcrypt-test docker://ttl.sh/nginx
