// docker.go — Docker inspection + data copy helpers used by the converter.
package v1convert

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
)

// ContainerInfo is the minimal slice of `docker inspect` output we need.
type ContainerInfo struct {
	Name          string
	Running       bool
	Image         string
	WorkingDir    string
	Entrypoint    []string
	Cmd           []string
	Env           []string
	User          string
	PublishedPort int    // host port bound to the container's exposed port
	ContainerPort int    // port inside the container
	VolumeName    string // docker volume name, empty when bind mount
	SourceDir     string // host path of the mount (/var/lib/docker/volumes/<vol>/_data or bind src)
	Destination   string // path inside container ("/app")
}

// dockerInspectPayload matches the fields of `docker inspect` we need.
type dockerInspectPayload struct {
	Name  string `json:"Name"`
	State struct {
		Running bool `json:"Running"`
	} `json:"State"`
	Config struct {
		WorkingDir   string   `json:"WorkingDir"`
		Entrypoint   []string `json:"Entrypoint"`
		Cmd          []string `json:"Cmd"`
		Env          []string `json:"Env"`
		User         string   `json:"User"`
		Image        string   `json:"Image"`
		ExposedPorts map[string]struct{} `json:"ExposedPorts"`
	} `json:"Config"`
	HostConfig struct {
		PortBindings map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"PortBindings"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type        string `json:"Type"`
		Name        string `json:"Name"`
		Source      string `json:"Source"`
		Destination string `json:"Destination"`
	} `json:"Mounts"`
}

// inspectContainer runs `docker inspect` and returns a ContainerInfo.
// Fails if the container does not exist. Running state is reported but not required.
func inspectContainer(ctx context.Context, name string) (*ContainerInfo, error) {
	out, err := exec.CommandContext(ctx, "docker", "inspect", name).Output()
	if err != nil {
		return nil, fmt.Errorf("docker inspect %s: %w", name, err)
	}

	var payloads []dockerInspectPayload
	if err := json.Unmarshal(out, &payloads); err != nil {
		return nil, fmt.Errorf("unmarshal docker inspect: %w", err)
	}
	if len(payloads) == 0 {
		return nil, fmt.Errorf("no docker inspect result for %s", name)
	}
	p := payloads[0]

	info := &ContainerInfo{
		Name:       name,
		Running:    p.State.Running,
		Image:      p.Config.Image,
		WorkingDir: p.Config.WorkingDir,
		Entrypoint: p.Config.Entrypoint,
		Cmd:        p.Config.Cmd,
		Env:        p.Config.Env,
		User:       p.Config.User,
	}

	// First non-empty /app or working-dir mount wins.
	for _, m := range p.Mounts {
		if m.Destination == info.WorkingDir || m.Destination == "/app" {
			info.VolumeName = m.Name
			info.SourceDir = m.Source
			info.Destination = m.Destination
			break
		}
	}
	if info.SourceDir == "" && len(p.Mounts) > 0 {
		info.VolumeName = p.Mounts[0].Name
		info.SourceDir = p.Mounts[0].Source
		info.Destination = p.Mounts[0].Destination
	}

	// Port mapping: take the first host binding we find.
	for containerPort, bindings := range p.HostConfig.PortBindings {
		if len(bindings) == 0 {
			continue
		}
		hp, err := strconv.Atoi(bindings[0].HostPort)
		if err != nil {
			continue
		}
		info.PublishedPort = hp
		// Parse "4001/tcp" → 4001.
		if cp := splitPort(containerPort); cp > 0 {
			info.ContainerPort = cp
		}
		break
	}

	return info, nil
}

// splitPort converts "4001/tcp" to 4001. Returns 0 if unparseable.
func splitPort(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '/' {
			n, _ := strconv.Atoi(s[:i])
			return n
		}
	}
	n, _ := strconv.Atoi(s)
	return n
}

// tarballDir creates a gzip tarball of srcDir at dstPath. Uses host `tar` for
// fidelity with Unix permissions + sparse handling.
func tarballDir(ctx context.Context, srcDir, dstPath string) error {
	_, err := runCmd(ctx, "tar", "-czf", dstPath, "-C", srcDir, ".")
	return err
}

// stopContainer issues `docker stop <name>` with a short grace period. Does not
// remove the container so we can rollback by restarting it.
func stopContainer(ctx context.Context, name string) error {
	_, err := runCmd(ctx, "docker", "stop", "-t", "10", name)
	return err
}

// startContainer starts a previously stopped container (used by rollback).
func startContainer(ctx context.Context, name string) error {
	_, err := runCmd(ctx, "docker", "start", name)
	return err
}

// pauseContainer SIGSTOPs all processes inside the container so filesystem
// state is frozen during backup.  Returns nil if the container is not running
// (already stopped containers don't need pausing).
func pauseContainer(ctx context.Context, name string) error {
	if !containerRunning(ctx, name) {
		return nil
	}
	_, err := runCmd(ctx, "docker", "pause", name)
	return err
}

// unpauseContainer reverses pauseContainer.  Safe to call on a non-paused
// container — errors are returned to the caller who can log-and-continue.
func unpauseContainer(ctx context.Context, name string) error {
	_, err := runCmd(ctx, "docker", "unpause", name)
	return err
}

// containerRunning returns true iff `docker inspect -f {{.State.Running}}`
// prints "true".  Used to decide whether pause/unpause is meaningful.
func containerRunning(ctx context.Context, name string) bool {
	out, err := exec.CommandContext(ctx, "docker", "inspect",
		"-f", "{{.State.Running}}", name).Output()
	if err != nil {
		return false
	}
	return string(bytesTrim(out)) == "true"
}

// bytesTrim trims trailing whitespace without importing strings/bytes just for this.
func bytesTrim(b []byte) []byte {
	for len(b) > 0 {
		c := b[len(b)-1]
		if c == '\n' || c == '\r' || c == ' ' || c == '\t' {
			b = b[:len(b)-1]
			continue
		}
		break
	}
	return b
}
