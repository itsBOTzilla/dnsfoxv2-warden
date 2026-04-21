// handlers_docker.go — docker-level operational jobs:
//   JOB_TYPE_DOCKER_RESTART  → docker restart <name>
//   JOB_TYPE_DOCKER_STOP     → docker stop <name>
//   JOB_TYPE_DOCKER_LOGS     → docker logs --tail N <name>
//
// Container names are strictly validated against the v1/v2 naming pattern so
// arbitrary privileged docker commands can't be executed via a crafted payload.
package jobs

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"time"

	wardenv1 "github.com/itsBOTzilla/dnsfoxv2-proto/gen/go/warden/v1"
)

// containerNameRE matches the v1/v2 container naming pattern.
// Keep this in sync with the allow-list on the API side.
var containerNameRE = regexp.MustCompile(`^(node|wp|php)_[A-Za-z0-9_-]+_(app|db|mgmt)$`)

// validateContainerName rejects anything that doesn't match the naming pattern.
func validateContainerName(payload map[string]interface{}) (string, error) {
	name, _ := payload["container_name"].(string)
	if name == "" {
		return "", fmt.Errorf("missing container_name")
	}
	if !containerNameRE.MatchString(name) {
		return "", fmt.Errorf("container_name %q does not match allowed pattern", name)
	}
	return name, nil
}

// handleDockerRestart runs `docker restart <name>` with a 30s timeout.
func (e *Executor) handleDockerRestart(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	name, err := validateContainerName(payload)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, "docker", "restart", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[jobs] docker restart %s failed: %v — output: %s", name, err, string(out))
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("docker restart: %v — %s", err, string(out))
	}
	log.Printf("[jobs] docker restart %s OK", name)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleDockerStop runs `docker stop <name>` with a 30s timeout.
func (e *Executor) handleDockerStop(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	name, err := validateContainerName(payload)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, "docker", "stop", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[jobs] docker stop %s failed: %v — output: %s", name, err, string(out))
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("docker stop: %v — %s", err, string(out))
	}
	log.Printf("[jobs] docker stop %s OK", name)
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, ""
}

// handleDockerLogs fetches the last N lines of a container's logs and
// returns them in the job result (via provisioningResultFmt hack — see below).
// The status reporter path doesn't carry an arbitrary result blob, so we stash
// the log output in the error_message field prefixed with "OK: " — the API
// polling loop extracts it. This is a deliberate, documented workaround that
// keeps the proto surface unchanged.
func (e *Executor) handleDockerLogs(ctx context.Context, payload map[string]interface{}) (
	wardenv1.ProvisioningStatus, string,
) {
	name, err := validateContainerName(payload)
	if err != nil {
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED, err.Error()
	}
	tail := 200
	if t, ok := payload["tail"].(float64); ok && int(t) > 0 && int(t) <= 2000 {
		tail = int(t)
	}
	c, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(c, "docker", "logs", "--tail", fmt.Sprintf("%d", tail), name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[jobs] docker logs %s failed: %v", name, err)
		return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_FAILED,
			fmt.Sprintf("docker logs: %v", err)
	}
	// Truncate absurdly long outputs so we don't blow up the heartbeat response.
	const maxBytes = 128 * 1024
	body := out
	if len(body) > maxBytes {
		body = body[len(body)-maxBytes:]
	}
	// Prefix with OK: so API knows the errMsg field is actually the payload.
	return wardenv1.ProvisioningStatus_PROVISIONING_STATUS_DONE, "LOGS:" + string(body)
}
