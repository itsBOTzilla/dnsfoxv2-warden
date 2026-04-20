// main.go — DNSFox v2 Warden Agent entry point.
//
// The warden runs two concurrent loops:
//   1. gRPC/Connect-Go server — receives provisioning jobs from the API
//   2. Heartbeat loop — pushes system metrics to the API every 15s and
//      receives pending jobs + config-sync directives in the response
//
// Both loops honour context cancellation so SIGTERM shuts everything down
// cleanly. Config is read entirely from environment variables (see
// internal/config/config.go).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/heartbeat"
	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
	wardenconnect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
)

// wardenHandler implements the WardenService gRPC interface.
// Individual RPCs will be wired to real handlers in later steps.
type wardenHandler struct{ wardenconnect.UnimplementedWardenServiceHandler }

// keep connect referenced to prevent mod tidy from dropping the import.
var _ = connect.CodeUnimplemented

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[warden] config error: %v", err)
	}

	log.Printf("[warden] dnsfox v2 warden agent starting")
	log.Printf("[warden]   server_id   : %s", cfg.ServerID)
	log.Printf("[warden]   grpc_port   : %s", cfg.GRPCPort)
	log.Printf("[warden]   environment : %s", cfg.Environment)
	log.Printf("[warden]   mariadb     : %s:%s", cfg.MariaDBHost, cfg.MariaDBPort)
	log.Printf("[warden]   redis       : %s:%s", cfg.RedisHost, cfg.RedisPort)
	log.Printf("[warden]   vhost_dir   : %s", cfg.NginxVhostDir)
	log.Printf("[warden]   docroot     : %s", cfg.DocrootBase)
	log.Printf("[warden]   log_dir     : %s", cfg.LogDir)
	log.Printf("[warden]   sites_domain: %s", cfg.SitesDomain)
	log.Printf("[warden]   api_url     : %s", cfg.APIUrl)

	// Root context cancelled on SIGTERM / SIGINT for graceful shutdown.
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Build the Connect-Go client used by the heartbeat to call the v2 API.
	// When the API is not yet running (early bootstrap), sends will fail and
	// be logged without crashing the process.
	apiClient := wardenconnect.NewWardenServiceClient(
		&http.Client{},
		cfg.APIUrl,
	)

	// Start heartbeat loop in background.
	reporter := heartbeat.NewReporter(apiClient, cfg, onSync, onJobs)
	go reporter.Run(ctx)

	// Register gRPC/Connect-Go handlers.
	mux := http.NewServeMux()
	mux.Handle(wardenconnect.NewWardenServiceHandler(&wardenHandler{}))

	addr := ":" + cfg.GRPCPort
	log.Printf("[warden] listening on %s (h2c)", addr)

	// Serve until context is cancelled, then return from ListenAndServe.
	// We use a goroutine so the shutdown signal is not missed.
	go func() {
		<-ctx.Done()
		log.Printf("[warden] shutting down")
	}()

	if err := http.ListenAndServe(addr, h2c.NewHandler(mux, &http2.Server{})); err != nil {
		log.Fatalf("[warden] server error: %v", err)
	}
}

// onSync handles a ConfigSyncDirective from the heartbeat response.
// In later steps this will trigger WAF rule updates, MU plugin syncs, etc.
func onSync(sync *wardenv1.ConfigSyncDirective) {
	log.Printf("[warden] config sync received (latest_version=%s)", sync.GetLatestWardenVersion())
}

// onJobs handles pending jobs delivered via the heartbeat response.
// In Step 2 these will be dispatched to the job executor.
func onJobs(jobs []*wardenv1.AgentJob) {
	for _, j := range jobs {
		log.Printf("[warden] job received: id=%s type=%s", j.GetJobId(), j.GetType())
	}
}
