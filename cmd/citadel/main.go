// Command citadel runs one region of the Citadel cloud.
//
//	citadel serve --region tuchanka-1 --listen 127.0.0.1:8420 --data ./data --bootstrap harness/bootstrap.json
//
// With --regions, the region joins a multi-region cloud: the registry names
// the home region, which serves the control-plane feed, and every other
// region follows it (ARCHITECTURE.md §7).
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
	"citadel/internal/lambda"
	"citadel/internal/region"
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
	regionName := fs.String("region", "tuchanka-1", "region name this process serves")
	listen := fs.String("listen", "127.0.0.1:8420", "address to listen on")
	dataDir := fs.String("data", "./data", "data directory (metadata db + blobs)")
	bootPath := fs.String("bootstrap", "", "bootstrap identities file (JSON)")
	conformance := fs.Bool("conformance", false, "enable test-only endpoints used by conformance suites")
	logFormat := fs.String("log", "json", "log format: json or text")
	gcInterval := fs.Duration("gc-interval", 10*time.Minute, "how often to sweep unreferenced blobs (0 disables)")
	gcGrace := fs.Duration("gc-grace", time.Hour, "minimum age of an unreferenced blob before it is deleted")
	regionsPath := fs.String("regions", "", "region registry file (JSON); omit to run a standalone region")
	antiEntropy := fs.Duration("anti-entropy", time.Minute, "how often replicated buckets and tables are compared with each other region (0 disables)")
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
	logger := slog.New(handler).With("region", *regionName)

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

	st, err := store.Open(context.Background(), *dataDir, *regionName)
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

	var (
		reg        *region.Registry
		follower   *region.Follower
		replicator *region.Replicator
		health     func() map[string]any
	)
	if *regionsPath != "" {
		if reg, err = region.Load(*regionsPath); err != nil {
			return err
		}
		if _, ok := reg.Get(*regionName); !ok {
			return fmt.Errorf("region %s is not in the registry %s", *regionName, *regionsPath)
		}
		if *regionName == reg.Home {
			health = func() map[string]any { return map[string]any{"role": "home", "home": reg.Home} }
		} else {
			follower = region.NewFollower(st, reg, *regionName, logger)
			health = follower.Status
		}
		control := health
		health = func() map[string]any {
			h := control()
			if replicator != nil {
				h["replication"] = replicator.Status(context.Background())
			}
			return h
		}
	}

	srv := api.New(api.Config{
		Region: *regionName, DataDir: *dataDir, Version: version,
		Bootstrap: boot, Conformance: *conformance, Logger: logger, Health: health,
	})
	iamHandler := iam.New(st, verifier, *regionName, logger)
	verifier.Session = iamHandler.CheckSession
	switch {
	case follower != nil:
		srv.Handle(api.SvcIAM, &region.Forwarder{
			Registry: reg, Local: iamHandler, HomeUp: follower.HomeUp, Logger: logger,
			Client: &http.Client{Timeout: 5 * time.Second},
		})
	case reg != nil:
		srv.HandleInternal(region.ControlPath, region.FeedHandler(st, reg, *regionName, logger))
		srv.Handle(api.SvcIAM, iamHandler)
	default:
		srv.Handle(api.SvcIAM, iamHandler)
	}
	srv.Handle(api.SvcSTS, iamHandler.STS())
	authz := iamHandler.Authorizer()
	s3Handler := s3.New(st, verifier, *regionName, logger)
	s3Handler.IAM = authz
	ddbHandler := ddb.New(st, verifier, *regionName, logger)
	ddbHandler.IAM = authz
	sqsHandler := sqs.New(st, verifier, *regionName, logger)
	sqsHandler.IAM = authz
	srv.Handle(api.SvcS3, s3Handler)
	srv.Handle(api.SvcDynamoDB, ddbHandler)
	srv.Handle(api.SvcSQS, sqsHandler)
	lambdaHandler := lambda.New(st, verifier, *regionName, *dataDir, logger)
	lambdaHandler.IAM = authz
	lambdaHandler.S3 = s3Handler
	lambdaHandler.SQS = sqsHandler
	s3Handler.Notify = lambdaHandler.NotificationTargets()
	defer lambdaHandler.Close()
	srv.Handle(api.SvcLambda, lambdaHandler)
	if reg != nil {
		replicator = region.NewReplicator(st, reg, *regionName, logger, s3Handler, ddbHandler)
		replicator.AntiEntropy = *antiEntropy
		ddbHandler.Regions = reg.Names
		ddbHandler.ReplicaReady = replicator.Repair
		for _, hs := range []map[string]http.Handler{s3Handler.InternalHandlers(), ddbHandler.InternalHandlers()} {
			for path, h := range hs {
				srv.HandleInternal(path, reg.Authenticate(h))
			}
		}
	}
	srv.Handle(api.SvcLogs, lambdaHandler.Logs())
	lambdaHandler.StartAsync()
	if err := lambdaHandler.StartPollers(context.Background()); err != nil {
		return fmt.Errorf("start event source mappings: %w", err)
	}

	var front http.Handler = srv
	if reg != nil {
		front = region.NewRouter(reg, *regionName, srv, logger)
	}
	httpSrv := &http.Server{
		Addr:              *listen,
		Handler:           front,
		ReadHeaderTimeout: 10 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := s3Handler.StartNotifier(ctx); err != nil {
		return fmt.Errorf("start s3 notifications: %w", err)
	}
	if follower != nil {
		go follower.Run(ctx)
	}
	if replicator != nil {
		go replicator.Run(ctx)
	}
	if *gcInterval > 0 {
		st.StartSweeper(ctx, *gcInterval, *gcGrace, logger)
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", *listen, "home", homeName(reg), "data", *dataDir, "conformance", *conformance, "version", version)
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

func homeName(reg *region.Registry) string {
	if reg == nil {
		return ""
	}
	return reg.Home
}
