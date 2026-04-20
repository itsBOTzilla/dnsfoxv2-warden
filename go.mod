module github.com/itsBOTzilla/dnsfoxv2-warden

go 1.26

require (
	connectrpc.com/connect v1.19.1
	github.com/itsBOTzilla/dnsfoxv2-proto v0.0.0
	golang.org/x/net v0.53.0
)

require (
	golang.org/x/text v0.36.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)

replace github.com/itsBOTzilla/dnsfoxv2-proto => ../proto
