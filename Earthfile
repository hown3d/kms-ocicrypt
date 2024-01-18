VERSION 0.7

proto-gen:
    FROM bufbuild/buf
    COPY buf.gen.yaml buf.yaml .
    RUN buf generate https://github.com/containers/ocicrypt.git --path utils/keyprovider
    SAVE ARTIFACT gen/go AS LOCAL gen/go

publish:
    FROM ghcr.io/ko-build/ko:latest
    ENV GOCACHE=/go/cache
    CACHE /go/cache
    COPY . kms-crypt
    WORKDIR kms-crypt
    ENV KO_DOCKER_REPO=ttl.sh/kms-crypt
    RUN ko build -B
