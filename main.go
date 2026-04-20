package main

import (
	"log"
	"net/http"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	wardenconnect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
)

// wardenHandler implements WardenService — methods return unimplemented until wired.
type wardenHandler struct{ wardenconnect.UnimplementedWardenServiceHandler }

// keep connect imported to avoid pruning during mod tidy.
var _ = connect.CodeUnimplemented

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("config error: %v", err)
	}

	log.Printf("dnsfox v2 warden starting")
	log.Printf("  server_id  : %s", cfg.ServerID)
	log.Printf("  grpc_port  : %s", cfg.GRPCPort)
	log.Printf("  environment: %s", cfg.Environment)
	log.Printf("  mariadb    : %s:%s", cfg.MariaDBHost, cfg.MariaDBPort)
	log.Printf("  redis      : %s:%s", cfg.RedisHost, cfg.RedisPort)
	log.Printf("  vhost_dir  : %s", cfg.NginxVhostDir)
	log.Printf("  docroot    : %s", cfg.DocrootBase)
	log.Printf("  log_dir    : %s", cfg.LogDir)
	log.Printf("  sites_domain: %s", cfg.SitesDomain)

	mux := http.NewServeMux()
	mux.Handle(wardenconnect.NewWardenServiceHandler(&wardenHandler{}))

	addr := ":" + cfg.GRPCPort
	log.Printf("listening on %s (h2c)", addr)

	if err := http.ListenAndServe(addr, h2c.NewHandler(mux, &http2.Server{})); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
