package kms

import (
	"context"
)

type Provider interface {
	Encrypt(ctx context.Context, plain []byte, keyId string) ([]byte, error)
	Decrypt(ctx context.Context, cipher []byte, keyId string) ([]byte, error)
}

// Register can be called from init() on a plugin in this package
// It will automatically be added to the Inputs map to be called externally
func register(name string, provider Provider) {
	Providers[name] = provider
}

// Providers registry
var Providers = map[string]Provider{}
