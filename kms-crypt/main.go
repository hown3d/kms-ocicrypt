package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"
	"log/slog"
	"net"
	"os"

	"github.com/containers/ocicrypt/keywrap/keyprovider"
	keyproviderpb "github.com/hown3d/containerd-kms-crypt/gen/go/utils/keyprovider"
	"github.com/hown3d/containerd-kms-crypt/kms"
	"github.com/hown3d/containerd-kms-crypt/kms/aws"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var port = 9666

// InterceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func main() {
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", port))
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to listen on port %v", port), "error", err)
		os.Exit(1)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			logging.UnaryServerInterceptor(InterceptorLogger(slog.Default())),
			// Add any other interceptor you want.
		),
		grpc.ChainStreamInterceptor(
			logging.StreamServerInterceptor(InterceptorLogger(slog.Default())),
			// Add any other interceptor you want.
		),
	)

	kmsProvider, err := aws.NewKMS()
	if err != nil {
		slog.Error("creating kms provider", "error", err)
	}
	keyproviderpb.RegisterKeyProviderServiceServer(grpcServer, &KeyProviderService{kmsProvider: kmsProvider})

	slog.Info(fmt.Sprintf("serving grpc server on :%d", port))
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("Failed to serve grpc server", "error", err)
		os.Exit(1)
	}
}

// Mock annotation packet, which goes into container image manifest
type annotationPacket struct {
	KeyUrl     string `json:"key_url"`
	WrappedKey []byte `json:"wrapped_key"`
}

type KeyProviderService struct {
	kmsProvider kms.Provider
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
	kmsKey, err := getKmsKey(decryptionParams)
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

	kmsKey, err := getKmsKey(encryptionParams)
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

func getKmsKey(params map[string][][]byte) (string, error) {
	for _, keys := range params {
		if len(keys) < 1 {
			return "", errors.New("missing key")
		}
		return string(keys[0]), nil
	}
	return "", errors.New("key missing in parameters")
}
