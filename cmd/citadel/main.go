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
	oracle := fs.Bool("oracle", false, "enable test-only endpoints used by oracle suites")
	logFormat := fs.String("log", "json", "log format: json or text")
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

	srv := api.New(api.Config{
		Region: *region, DataDir: *dataDir, Version: version,
		Bootstrap: boot, Oracle: *oracle, Logger: logger,
	})

	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           srv,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", *listen, "data", *dataDir, "oracle", *oracle, "version", version)
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
