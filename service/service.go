package service

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	keyproviderpb "github.com/hown3d/kms-ocicrypt/gen/go/utils/keyprovider"
	"github.com/hown3d/kms-ocicrypt/kms"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Mock annotation packet, which goes into container image manifest
type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
}

type KeyProviderService struct {
	kmsProvider     kms.Provider
	keyProviderName string
}

func NewKeyProviderService(kmsProvider kms.Provider, keyproviderName string) *KeyProviderService {
	return &KeyProviderService{
		kmsProvider:     kmsProvider,
		keyProviderName: keyproviderName,
	}
}

// Interface compliance
var _ keyproviderpb.KeyProviderServiceServer = (*KeyProviderService)(nil)

// UnWrapKey implements keyprovider.KeyProviderServiceServer.
func (s *KeyProviderService) UnWrapKey(ctx context.Context, input *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	var protoInput keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.Unmarshal(input.KeyProviderKeyWrapProtocolInput, &protoInput)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid protocol input")
	}

	if protoInput.Operation != keyprovider.OpKeyUnwrap {
		return nil, status.Error(codes.InvalidArgument, "wrong operation")
	}

	decryptionParams := protoInput.KeyUnwrapParams.Dc.Parameters
	if decryptionParams == nil {
		return nil, status.Error(codes.InvalidArgument, "missing decryption parameters")
	}

	var packet annotationPacket
	err = json.Unmarshal(protoInput.KeyUnwrapParams.Annotation, &packet)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "unmarshal annotationPacket: %v", err)
	}
	kmsKey, err := s.getKmsKey(decryptionParams)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	decryptedKey, err := s.kmsProvider.Decrypt(ctx, packet.WrappedKey, kmsKey)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "decrypting key: %s", err)
	}

	protoOutput := &keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyUnwrapResults: keyprovider.KeyUnwrapResults{OptsData: decryptedKey},
	}
	serialized, err := json.Marshal(protoOutput)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal protocol output: %v", err)
	}

	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: serialized,
	}, nil
}

// WrapKey implements keyprovider.KeyProviderServiceServer.
func (s *KeyProviderService) WrapKey(ctx context.Context, input *keyproviderpb.KeyProviderKeyWrapProtocolInput) (*keyproviderpb.KeyProviderKeyWrapProtocolOutput, error) {
	var protoInput keyprovider.KeyProviderKeyWrapProtocolInput
	err := json.Unmarshal(input.KeyProviderKeyWrapProtocolInput, &protoInput)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid protocol input")
	}

	if protoInput.Operation != keyprovider.OpKeyWrap {
		return nil, status.Error(codes.InvalidArgument, "wrong operation")
	}

	encryptionParams := protoInput.KeyWrapParams.Ec.Parameters
	if encryptionParams == nil {
		return nil, status.Error(codes.InvalidArgument, "missing encryption parameters")
	}

	kmsKey, err := s.getKmsKey(encryptionParams)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	cipherText, err := s.kmsProvider.Encrypt(ctx, protoInput.KeyWrapParams.OptsData, kmsKey)
	if err != nil {
		return nil, status.Error(codes.Internal, err.Error())
	}

	packet := annotationPacket{
		KeyUrl:     kmsKey,
		WrappedKey: cipherText,
	}
	packetJson, err := json.Marshal(packet)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal annotationPacket: %v", err)
	}

	protoOutput := &keyprovider.KeyProviderKeyWrapProtocolOutput{
		KeyWrapResults: keyprovider.KeyWrapResults{
			Annotation: packetJson,
		},
	}
	out, err := json.Marshal(protoOutput)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "marshal protocol output: %v", err)
	}

	return &keyproviderpb.KeyProviderKeyWrapProtocolOutput{
		KeyProviderKeyWrapProtocolOutput: out,
	}, nil
}

func (s *KeyProviderService) getKmsKey(params map[string][][]byte) (string, error) {
	slog.Info("getKmsKey", "request params", params)
	keys, ok := params[s.keyProviderName]
	if !ok {
		return "", errors.New("keyprovider is missing in parameters")
	}
	if len(keys) < 1 {
		return "", errors.New("missing key")
	}
	return string(keys[0]), nil
}
