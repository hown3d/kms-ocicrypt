# syntax=docker/dockerfile:1
ARG BUILDSPEC=git
FROM golang:1.21 as imgcrypt-build
ADD https://github.com/containerd/imgcrypt.git#v1.1.9 /imgcrypt
WORKDIR /imgcrypt
ENV CGO_ENABLED=0
RUN go build -ldflags='-s -w' -o ctd-decoder ./cmd/ctd-decoder


FROM golang:1.21 as containerd-git-build
ADD  --keep-git-dir=true  https://github.com/hown3d/containerd.git#pod-decryption-model /containerd
WORKDIR /containerd
ENV CGO_ENABLED=0
RUN make STATIC=1

FROM scratch as containerd-local-build
COPY containerd /containerd/bin/

FROM containerd-$BUILDSPEC-build as containerd-build

FROM kindest/node:v1.29.0
# config done here: https://github.com/containerd/containerd/blob/1677a17964311325ed1c31e2c0a3589ce6d5c30d/cmd/containerd/command/config.go#L145-L146
ADD kms-crypt/test/ocicrypt.json /etc/containerd/ocicrypt/ocicrypt_keyprovider.conf
COPY --from=imgcrypt-build /imgcrypt/ctd-decoder /bin
COPY --from=containerd-build /containerd/bin/containerd /usr/local/bin/
COPY containerd.toml /etc/containerd/config.toml
RUN mkdir -p /etc/containerd/ocicrypt/keys
