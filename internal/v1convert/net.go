// net.go — tiny helper so nodejs.go does not need a direct net import.
package v1convert

import (
	"fmt"
	"net"
)

// netListen binds 127.0.0.1:<port> and returns the listener so the caller
// can close it immediately — used to probe for free ports.
func netListen(port int) (net.Listener, error) {
	return net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
}
