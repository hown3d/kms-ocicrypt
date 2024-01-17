package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"

	"github.com/grpc-ecosystem/go-grpc-middleware/v2/interceptors/logging"

	keyproviderpb "github.com/hown3d/containerd-kms-crypt/gen/go/utils/keyprovider"
	"github.com/hown3d/containerd-kms-crypt/kms"
	"github.com/hown3d/containerd-kms-crypt/service"
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
	lis, err := net.Listen("tcp", fmt.Sprintf("0.0.0.0:%d", *port))
	if err != nil {
		slog.Error(fmt.Sprintf("Failed to listen on port %v", *port), "error", err)
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

	kmsProvider, ok := kms.Providers[*kmsProviderName]
	if !ok {
		log.Fatalf("specified kms provider %v is not registered", *kmsProviderName)
	}
	keyproviderpb.RegisterKeyProviderServiceServer(grpcServer, service.NewKeyProviderService(kmsProvider))

	slog.Info(fmt.Sprintf("serving grpc server on :%d", *port))
	if err := grpcServer.Serve(lis); err != nil {
		slog.Error("Failed to serve grpc server", "error", err)
		os.Exit(1)
	}
}
