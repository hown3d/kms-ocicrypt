package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"

	keyproviderpb "github.com/hown3d/kms-ocicrypt/gen/go/utils/keyprovider"
	"github.com/hown3d/kms-ocicrypt/kms"
	"github.com/hown3d/kms-ocicrypt/service"
	"google.golang.org/grpc"
)

var (
	port                    = flag.Int("port", 9666, "port to bind grpc server to")
	keyProviderName *string = flag.String("keyprovider-name", "kms-crypt", "name of the keyprovider in ocicrypt config")
	kmsProviderName *string = flag.String("kms-provider", "aws", "which kms provider to use. Implemented providers: aws")
)

// InterceptorLogger adapts slog logger to interceptor logger.
// This code is simple enough to be copied and not imported.
func InterceptorLogger(l *slog.Logger) logging.Logger {
	return logging.LoggerFunc(func(ctx context.Context, lvl logging.Level, msg string, fields ...any) {
		l.Log(ctx, slog.Level(lvl), msg, fields...)
	})
}

func main() {
	flag.Parse()

	err := createOcicryptKeyproviderConfig()
	if err != nil {
		log.Fatalf("error creating ocicrypt keyprovider config: %s", err)
	}

	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		log.Fatalf("Failed to listen on port %v: %v", *port, err)
	}

	grpcServer := grpc.NewServer(
		grpc.ChainUnaryInterceptor(
			logging.UnaryServerInterceptor(InterceptorLogger(slog.Default())),
		),
		grpc.ChainStreamInterceptor(
			logging.StreamServerInterceptor(InterceptorLogger(slog.Default())),
		),
	)

	kmsProvider, ok := kms.Providers[*kmsProviderName]
	if !ok {
		log.Fatalf("specified kms provider %v is not registered", *kmsProviderName)
	}
	keyproviderpb.RegisterKeyProviderServiceServer(grpcServer, service.NewKeyProviderService(kmsProvider, *keyProviderName))

	slog.Info(fmt.Sprintf("serving grpc server on :%d", *port))
	if err := grpcServer.Serve(lis); err != nil {
		log.Fatalf("Failed to serve grpc server: %s", err)
	}
}

type OcicryptKeyproviderConfig struct {
	KeyProviders map[string]struct {
		GRPC string `json:"grpc"`
	} `json:"key-providers"`
}

const keyproviderFilepath = "/etc/containerd/ocicrypt/ocicrypt_keyprovider.conf"

func createOcicryptKeyproviderConfig() error {
	ip := os.Getenv("POD_IP")
	cfg := OcicryptKeyproviderConfig{
		KeyProviders: map[string]struct {
			GRPC string `json:"grpc"`
		}{
			*keyProviderName: {
				GRPC: fmt.Sprintf("%v:%d", ip, *port),
			},
		},
	}
	slog.Info("generateOcicryptKeyproviderConfig", "config", cfg)
	cfgBytes, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}

	f, err := os.Create(keyproviderFilepath)
	if err != nil {
		return err
	}

	_, err = f.Write(cfgBytes)
	if err != nil {
		return err
	}
	return nil
}
