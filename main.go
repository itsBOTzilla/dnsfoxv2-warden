package main

import (
	"log"
	"net/http"
	"os"

	"connectrpc.com/connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"

	wardenconnect "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1/wardenv1connect"
)

// wardenHandler implements WardenService — all methods return unimplemented.
type wardenHandler struct{ wardenconnect.UnimplementedWardenServiceHandler }

// ensure connect is referenced to avoid import pruning during mod tidy.
var _ = connect.CodeUnimplemented

func main() {
	port := os.Getenv("GRPC_PORT")
	if port == "" {
		port = "9200"
	}
	serverID := os.Getenv("SERVER_ID")
	if serverID == "" {
		serverID = "local"
	}
	env := os.Getenv("ENVIRONMENT")
	if env == "" {
		env = "development"
	}

	mux := http.NewServeMux()

	mux.Handle(wardenconnect.NewWardenServiceHandler(&wardenHandler{}))

	addr := ":" + port
	log.Printf("dnsfox v2 warden starting — server %s — port %s — env %s", serverID, port, env)

	if err := http.ListenAndServe(
		addr,
		h2c.NewHandler(mux, &http2.Server{}),
	); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
