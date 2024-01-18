package kms

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/config"
	aws_kms "github.com/aws/aws-sdk-go-v2/service/kms"
)

func init() {
	awsKms, err := newKMS()
	if err != nil {
		log.Fatal(err)
	}
	register("aws", awsKms)
}

type awsKms struct {
	client *aws_kms.Client
}

// Interface compliance
var _ Provider = (*awsKms)(nil)

// Decrypt implements kms.KMS.
func (k *awsKms) Decrypt(ctx context.Context, cipher []byte, keyId string) ([]byte, error) {
	req := &aws_kms.DecryptInput{
		KeyId:          &keyId,
		CiphertextBlob: cipher,
	}
	resp, err := k.client.Decrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

// Encrypt implements kms.KMS.
func (k *awsKms) Encrypt(ctx context.Context, plain []byte, keyId string) ([]byte, error) {
	req := &aws_kms.EncryptInput{
		KeyId:     &keyId,
		Plaintext: plain,
	}
	resp, err := k.client.Encrypt(ctx, req)
	if err != nil {
		return nil, err
	}
	return resp.CiphertextBlob, nil
}

func newKMS() (*awsKms, error) {
	// Using the SDK's default configuration, loading additional config
	// and credentials values from the environment variables, shared
	// credentials, and shared configuration files
	cfg, err := config.LoadDefaultConfig(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("unable to load SDK config: %w", err)
	}

	client := aws_kms.NewFromConfig(cfg)
	return &awsKms{client: client}, nil
}
