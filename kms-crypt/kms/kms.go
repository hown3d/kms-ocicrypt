package kms

import (
	"context"

	"github.com/hown3d/containerd-kms-crypt/kms/aws"
)

type Provider interface {
	Encrypt(ctx context.Context, plain []byte, keyId string) ([]byte, error)
	Decrypt(ctx context.Context, cipher []byte, keyId string) ([]byte, error)
}

// Interface compliance
var _ Provider = (*aws.KMS)(nil)
