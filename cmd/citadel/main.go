// Command citadel runs one region of the Citadel cloud.
//
//	citadel serve --region tuchanka-1 --listen 127.0.0.1:8420 --data ./data --bootstrap harness/bootstrap.json
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"citadel/internal/api"
	"citadel/internal/bootstrap"
	"citadel/internal/ddb"
	"citadel/internal/iam"
	"citadel/internal/s3"
	"citadel/internal/sigv4"
	"citadel/internal/sqs"
	"citadel/internal/store"
)

// version is set at build time: -ldflags "-X main.version=$(git describe --always)".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "serve":
		if err := serve(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "citadel:", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println(version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: citadel serve [flags] | citadel version")
}

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	region := fs.String("region", "tuchanka-1", "region name this process serves")
	listen := fs.String("listen", "127.0.0.1:8420", "address to listen on")
	dataDir := fs.String("data", "./data", "data directory (metadata db + blobs)")
	bootPath := fs.String("bootstrap", "", "bootstrap identities file (JSON)")
	conformance := fs.Bool("conformance", false, "enable test-only endpoints used by conformance suites")
	logFormat := fs.String("log", "json", "log format: json or text")
	gcInterval := fs.Duration("gc-interval", 10*time.Minute, "how often to sweep unreferenced blobs (0 disables)")
	gcGrace := fs.Duration("gc-grace", time.Hour, "minimum age of an unreferenced blob before it is deleted")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// Stay small on an 8 GB laptop unless the operator says otherwise.
	if os.Getenv("GOMEMLIMIT") == "" {
		debug.SetMemoryLimit(256 << 20)
	}

	var handler slog.Handler = slog.NewJSONHandler(os.Stderr, nil)
	if *logFormat == "text" {
		handler = slog.NewTextHandler(os.Stderr, nil)
	}
	logger := slog.New(handler).With("region", *region)

	if err := os.MkdirAll(*dataDir, 0o755); err != nil {
		return fmt.Errorf("create data dir: %w", err)
	}

	var boot *bootstrap.File
	if *bootPath != "" {
		b, err := bootstrap.Load(*bootPath)
		if err != nil {
			return err
		}
		boot = b
		logger.Info("bootstrap loaded", "accounts", len(b.Accounts), "keys", b.KeyCount())
	}

	st, err := store.Open(context.Background(), *dataDir, *region)
	if err != nil {
		return fmt.Errorf("open store: %w", err)
	}
	defer st.Close()
	if err := st.SeedIdentities(context.Background(), boot); err != nil {
		return fmt.Errorf("seed identities: %w", err)
	}
	verifier := &sigv4.Verifier{Lookup: func(ctx context.Context, accessKey string) (string, error) {
		secret, _, err := st.LookupKey(ctx, accessKey)
		if errors.Is(err, store.ErrNotFound) {
			return "", sigv4.ErrUnknownKey
		}
		return secret, err
	}}

	srv := api.New(api.Config{
		Region: *region, DataDir: *dataDir, Version: version,
		Bootstrap: boot, Conformance: *conformance, Logger: logger,
	})
	iamHandler := iam.New(st, verifier, *region, logger)
	verifier.Session = iamHandler.CheckSession
	srv.Handle(api.SvcIAM, iamHandler)
	srv.Handle(api.SvcSTS, iamHandler.STS())
	srv.Handle(api.SvcS3, s3.New(st, verifier, *region, logger))
	srv.Handle(api.SvcDynamoDB, ddb.New(st, verifier, *region, logger))
	srv.Handle(api.SvcSQS, sqs.New(st, verifier, *region, logger))

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if *gcInterval > 0 {
		st.StartSweeper(ctx, *gcInterval, *gcGrace, logger)
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", *listen, "data", *dataDir, "conformance", *conformance, "version", version)
		errCh <- httpSrv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpSrv.Shutdown(shutdownCtx)
	}
	return nil
}
