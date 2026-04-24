module github.com/itsBOTzilla/dnsfoxv2-warden

go 1.26

require (
	connectrpc.com/connect v1.19.2
	github.com/creack/pty v1.1.24
	github.com/gorilla/websocket v1.5.3
	github.com/itsBOTzilla/dnsfoxv2-proto v0.0.0
	golang.org/x/net v0.53.0
	google.golang.org/protobuf v1.36.11
)

require golang.org/x/text v0.36.0 // indirect

replace github.com/itsBOTzilla/dnsfoxv2-proto => ../dnsfoxv2-proto
