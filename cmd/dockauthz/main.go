package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/swarm-deploy/dockauthz/internal/audit"
	"github.com/swarm-deploy/dockauthz/internal/authz"
	"github.com/swarm-deploy/dockauthz/internal/config"
	"github.com/swarm-deploy/dockauthz/internal/dockerapi"
	"github.com/swarm-deploy/dockauthz/internal/policy"
	"github.com/swarm-deploy/dockauthz/internal/telemetry"
	"github.com/swarm-deploy/dockauthz/internal/transport"
)

var version = "dev"

const shutdownTimeout = 8 * time.Second

func main() {
	slog.SetDefault(audit.NewLogger(os.Stdout))
	if err := run(); err != nil {
		slog.ErrorContext(context.Background(), "dockauthz stopped", "error", err)
		os.Exit(1)
	}
}

func run() error {
	path := flag.String("config", config.DefaultPath, "local YAML configuration file")
	flag.Parse()
	if flag.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, err := config.Load(*path)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	tel, err := telemetry.Setup(ctx, cfg.Telemetry, version)
	if err != nil {
		return err
	}
	defer func() {
		shutdown, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if shutdownErr := tel.Shutdown(shutdown); shutdownErr != nil {
			slog.ErrorContext(shutdown, "telemetry shutdown failed")
		}
	}()
	token, err := dockerapi.NewToken()
	if err != nil {
		return errors.New("cannot create internal authorization token")
	}
	client := dockerapi.New("/var/run/docker.sock", token, tel.Observer)
	defer client.Close()
	plugin, err := authz.New(cfg, token, policy.New(client, tel.Observer), tel.Observer, slog.Default())
	if err != nil {
		return err
	}
	slog.InfoContext(ctx, "starting dockauthz", "version", version)
	return transport.New(plugin).ServeUnix(ctx, "/run/docker/plugins/dockauthz.sock")
}
