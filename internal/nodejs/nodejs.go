// Package nodejs provisions Node.js applications directly on the host.
// Unlike v1 (which ran Node.js in Docker per-site containers), v2 runs Node.js
// as systemd services under per-site user accounts, using the host Node.js
// installation (currently v24). This removes Docker overhead while preserving
// full process isolation via cgroups and separate Linux users.
//
// Provisioning order:
//  1. Create system user and document root
//  2. Apply cgroup limits via systemd slice
//  3. Optionally create MariaDB database
//  4. Allocate a free port (4000–5000)
//  5. Write .env file with all environment variables
//  6. Clone git repo into docroot if provided
//  7. Run build command if provided
//  8. Write and enable systemd service unit
//  9. Write nginx reverse-proxy vhost
// 10. Start service and reload nginx
package nodejs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/cgroups"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/config"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/mariadb"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/nginx"
	"github.com/itsBOTzilla/dnsfoxv2-warden/internal/provisioning"
)

// safeCmdPattern allows typical shell commands used in build/start scripts
// but blocks injection characters (;, &, |, $, backtick, parens, etc.).
var safeCmdPattern = regexp.MustCompile(`^[a-zA-Z0-9\s._\-/:=@,]+$`)

// safeEnvKeyPattern validates environment variable names.
var safeEnvKeyPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// blockedEnvKeys are system-level variables that customers must not override.
var blockedEnvKeys = map[string]bool{
	"PATH": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"HOME": true, "USER": true, "SHELL": true,
	"NODE_OPTIONS": true, "NODE_PATH": true,
	"PROMPT_COMMAND": true, "BASH_ENV": true,
}

// NodeParams carries Node.js-specific provisioning parameters.
// Passed as JSON in ProvisionSiteRequest.EncryptedCredentials.
type NodeParams struct {
	// StartCommand is the command to run the app, e.g. "npm start" or "node server.js".
	StartCommand string `json:"start_command"`
	// BuildCommand is run once before starting, e.g. "npm run build". Optional.
	BuildCommand string `json:"build_command"`
	// EnvVars are injected into the .env file and the systemd service environment.
	EnvVars map[string]string `json:"env_vars"`
	// DatabaseEnabled creates a MariaDB database for the app.
	DatabaseEnabled bool `json:"database_enabled"`
	// GitRepoURL is cloned into the docroot before building. Optional.
	GitRepoURL string `json:"git_repo_url"`
	// GitBranch defaults to "main" when empty.
	GitBranch string `json:"git_branch"`
	// IsStatic marks this as a static HTML/SPA site. The provisioner runs
	// /usr/bin/serve public -s -p PORT inside the cgroup slice instead of node.
	IsStatic bool `json:"is_static"`
}

// DetectionResult holds the outcome of framework auto-detection.
// Framework is empty when the user supplied their own start command
// or when no recognisable framework was found.
type DetectionResult struct {
	Framework    string // "nextjs", "nuxt", "remix", or ""
	StartCommand string // e.g. "node .next/standalone/server.js"
	BuildCommand string // e.g. "npm run build"
}

// detectFramework inspects docroot for framework config files and package.json
// scripts, returning detected start/build commands. The returned commands are
// in "human" form (e.g. "node .next/standalone/server.js") — writeSystemdUnit
// resolves them to absolute binary paths.
func detectFramework(docroot string) DetectionResult {
	// Priority 1: Next.js
	for _, f := range []string{"next.config.js", "next.config.mjs", "next.config.ts"} {
		if fileExists(filepath.Join(docroot, f)) {
			return DetectionResult{
				Framework:    "nextjs",
				StartCommand: "node .next/standalone/server.js",
				BuildCommand: "npm run build",
			}
		}
	}
	// Priority 2: Nuxt
	for _, f := range []string{"nuxt.config.js", "nuxt.config.mjs", "nuxt.config.ts"} {
		if fileExists(filepath.Join(docroot, f)) {
			return DetectionResult{
				Framework:    "nuxt",
				StartCommand: "node .output/server/index.mjs",
				BuildCommand: "npm run build",
			}
		}
	}
	// Priority 3: Remix
	for _, f := range []string{"remix.config.js", "remix.config.mjs", "remix.config.ts"} {
		if fileExists(filepath.Join(docroot, f)) {
			return DetectionResult{
				Framework:    "remix",
				StartCommand: "npm run start",
				BuildCommand: "npm run build",
			}
		}
	}
	// Fallback: use package.json scripts if present.
	scripts := readPackageJSONScripts(docroot)
	var startCmd, buildCmd string
	if _, ok := scripts["start"]; ok {
		startCmd = "npm run start"
	} else {
		startCmd = "server.js"
	}
	if _, ok := scripts["build"]; ok {
		buildCmd = "npm run build"
	}
	return DetectionResult{StartCommand: startCmd, BuildCommand: buildCmd}
}

// readPackageJSONScripts parses the "scripts" object from package.json in docroot.
func readPackageJSONScripts(docroot string) map[string]string {
	data, err := os.ReadFile(filepath.Join(docroot, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	return pkg.Scripts
}

// fileExists returns true if path exists on disk.
func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// Provisioner provisions Node.js sites on the host.
type Provisioner struct {
	cfg     *config.Config
	cgroups *cgroups.Manager
	mariadb *mariadb.Manager
	nginx   *nginx.Manager
}

// New creates a new Node.js Provisioner.
func New(cfg *config.Config) *Provisioner {
	return &Provisioner{
		cfg:     cfg,
		cgroups: cgroups.NewManager(),
		mariadb: mariadb.NewManager(),
		nginx:   nginx.NewManager(),
	}
}

// ProvisionNodeJS sets up a complete Node.js hosting environment.
// It does NOT call ProvisionSite — it manages its own user, docroot, and nginx.
// Returns the detected framework name (empty when user supplied their own command).
func (p *Provisioner) ProvisionNodeJS(ctx context.Context, siteCfg provisioning.SiteConfig, params NodeParams) (string, error) {
	if err := validateParams(params); err != nil {
		return "", fmt.Errorf("invalid params: %w", err)
	}

	username := provisioning.SiteUsername(siteCfg.SiteID)
	docroot := fmt.Sprintf("/var/www/%s/public", username)

	if err := provisioning.CreateSystemUser(username); err != nil {
		return "", fmt.Errorf("create user: %w", err)
	}
	if err := provisioning.AddToGroup(username, "www-data"); err != nil {
		return "", fmt.Errorf("add www-data to group: %w", err)
	}
	if err := provisioning.CreateDocumentRoot(docroot, username); err != nil {
		return "", fmt.Errorf("create docroot: %w", err)
	}

	limits, ok := provisioning.PlanLimits[siteCfg.Plan]
	if !ok {
		limits = provisioning.PlanLimits["fox"]
	}
	if err := p.cgroups.ApplyLimits(siteCfg.SiteID, username, limits); err != nil {
		return "", fmt.Errorf("apply cgroup limits: %w", err)
	}

	if params.DatabaseEnabled {
		if err := p.mariadb.CreateSiteDatabase(siteCfg.SiteID, username); err != nil {
			return "", fmt.Errorf("create database: %w", err)
		}
		log.Printf("[nodejs] created mariadb database for %s", siteCfg.SiteID)
	}

	port, err := allocatePort(4000, 5000)
	if err != nil {
		return "", fmt.Errorf("allocate port: %w", err)
	}
	log.Printf("[nodejs] allocated port %d for %s", port, siteCfg.Domain)

	if err := p.writeEnvFile(username, siteCfg, params, port); err != nil {
		return "", fmt.Errorf("write env file: %w", err)
	}

	var detectedFramework string
	if !params.IsStatic {
		if params.GitRepoURL != "" {
			if err := cloneRepo(ctx, params.GitRepoURL, params.GitBranch, docroot, username); err != nil {
				return "", fmt.Errorf("git clone: %w", err)
			}
		}

		// Run npm install when package.json is present (before build command).
		pkgJSON := filepath.Join(docroot, "package.json")
		if _, err := os.Stat(pkgJSON); err == nil {
			if err := runAsUser(username, docroot, "npm install --production=false"); err != nil {
				// Non-fatal: log the warning and proceed to the build command.
				log.Printf("[nodejs] npm install warning for %s: %v", siteCfg.SiteID, err)
			}
		}

		// Auto-detect framework and fill blank StartCommand / BuildCommand.
		if params.StartCommand == "" || params.BuildCommand == "" {
			det := detectFramework(docroot)
			detectedFramework = det.Framework
			if params.StartCommand == "" {
				params.StartCommand = det.StartCommand
			}
			if params.BuildCommand == "" {
				params.BuildCommand = det.BuildCommand
			}
			if det.Framework != "" {
				log.Printf("[nodejs] detected framework %q for %s — start=%q build=%q",
					det.Framework, siteCfg.SiteID, params.StartCommand, params.BuildCommand)
			}
		}

		if params.BuildCommand != "" {
			if err := runAsUser(username, docroot, params.BuildCommand); err != nil {
				return "", fmt.Errorf("build command: %w", err)
			}
		}
	}

	if err := p.writeSystemdUnit(siteCfg.SiteID, username, docroot, params, port); err != nil {
		return "", fmt.Errorf("write systemd unit: %w", err)
	}

	// Compute the internal subdomain alias (first 8 chars of site UUID).
	shortID := siteCfg.SiteID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	subdomain := fmt.Sprintf("%s.sites.dnsfox.com", shortID)

	if err := p.nginx.WriteProxyVhost(nginx.ProxyVhostConfig{
		SiteID:    siteCfg.SiteID,
		Domain:    siteCfg.Domain,
		Subdomain: subdomain,
		Port:      port,
	}); err != nil {
		return "", fmt.Errorf("write nginx vhost: %w", err)
	}

	exec.Command("systemctl", "daemon-reload").Run() //nolint:errcheck
	svcName := serviceUnit(siteCfg.SiteID)
	exec.Command("systemctl", "enable", "--now", svcName).Run() //nolint:errcheck

	if err := provisioning.ReloadNginx(); err != nil {
		return "", fmt.Errorf("reload nginx: %w", err)
	}

	log.Printf("[nodejs] provisioning complete for %s on port %d", siteCfg.Domain, port)
	return detectedFramework, nil
}

// DeprovisionNodeJS tears down all resources for a Node.js site.
func (p *Provisioner) DeprovisionNodeJS(ctx context.Context, siteID string) error {
	username := provisioning.SiteUsername(siteID)
	svcName := serviceUnit(siteID)

	exec.Command("systemctl", "disable", "--now", svcName).Run()       //nolint:errcheck
	os.Remove(fmt.Sprintf("/etc/systemd/system/%s", svcName))          //nolint:errcheck
	exec.Command("systemctl", "daemon-reload").Run()                   //nolint:errcheck
	p.nginx.RemoveVhost(siteID)                                         //nolint:errcheck
	p.cgroups.RemoveLimits(siteID)                                      //nolint:errcheck
	p.mariadb.DropSiteDatabase(siteID, username)                        //nolint:errcheck
	exec.Command("userdel", "-r", username).Run()                       //nolint:errcheck
	provisioning.ReloadNginx()                                           //nolint:errcheck

	log.Printf("[nodejs] deprovisioning complete for %s", siteID)
	return nil
}

// writeEnvFile writes /var/www/{username}/.env with app environment variables.
func (p *Provisioner) writeEnvFile(username string, siteCfg provisioning.SiteConfig, params NodeParams, port int) error {
	path := fmt.Sprintf("/var/www/%s/.env", username)

	var sb strings.Builder
	sb.WriteString("# DNSFox v2 — auto-generated env for " + siteCfg.SiteID + "\n")
	sb.WriteString(fmt.Sprintf("PORT=%d\n", port))
	sb.WriteString(fmt.Sprintf("NODE_ENV=production\n"))
	sb.WriteString(fmt.Sprintf("DNSFOX_INSTANCE_ID=%s\n", siteCfg.SiteID))

	if params.DatabaseEnabled {
		credsPath := fmt.Sprintf("/var/www/%s/.db_credentials", username)
		if dbName, dbUser, dbPass, err := parseDBCreds(credsPath); err == nil {
			sb.WriteString(fmt.Sprintf("DB_HOST=127.0.0.1\nDB_PORT=%s\nDB_NAME=%s\nDB_USER=%s\nDB_PASS=%s\n",
				p.cfg.MariaDBPort, dbName, dbUser, dbPass))
		}
	}

	sb.WriteString(fmt.Sprintf("REDIS_HOST=%s\nREDIS_PORT=%s\nREDIS_PREFIX=site_%s:\n",
		p.cfg.RedisHost, p.cfg.RedisPort, siteCfg.SiteID))
	if p.cfg.RedisPassword != "" {
		sb.WriteString(fmt.Sprintf("REDIS_PASSWORD=%s\n", p.cfg.RedisPassword))
	}

	for k, v := range params.EnvVars {
		sb.WriteString(fmt.Sprintf("%s=%s\n", k, v))
	}

	return os.WriteFile(path, []byte(sb.String()), 0600)
}

// systemdUnitTemplate defines the systemd service for a Node.js or static site.
// ExecStart is the full command — either "/usr/bin/node server.js" for Node.js
// or "/usr/bin/serve public -s -p PORT" for static HTML sites.
const systemdUnitTemplate = `[Unit]
Description=DNSFox v2 site {{.SiteID}}
After=network.target

[Service]
Type=simple
User={{.Username}}
Group={{.Username}}
WorkingDirectory={{.Docroot}}
EnvironmentFile=/var/www/{{.Username}}/.env
ExecStart={{.ExecStart}}
Restart=always
RestartSec=5
Slice=dnsfox-site-{{.SiteID}}.slice

[Install]
WantedBy=multi-user.target
`

type unitData struct {
	SiteID    string
	Username  string
	Docroot   string
	ExecStart string
}

// resolveExecStart converts a human-form start command into a systemd ExecStart
// with an absolute binary path. Commands prefixed with "npm", "npx", or "node"
// are resolved to their /usr/bin counterpart; bare script names are run via node.
func resolveExecStart(startCmd string) string {
	switch {
	case strings.HasPrefix(startCmd, "npm "):
		return "/usr/bin/npm " + strings.TrimPrefix(startCmd, "npm ")
	case strings.HasPrefix(startCmd, "npx "):
		return "/usr/bin/npx " + strings.TrimPrefix(startCmd, "npx ")
	case strings.HasPrefix(startCmd, "node "):
		return "/usr/bin/node " + strings.TrimPrefix(startCmd, "node ")
	default:
		return "/usr/bin/node " + startCmd
	}
}

// writeSystemdUnit writes a systemd service unit for a Node.js app or static site.
// For static (IsStatic=true): ExecStart = /usr/bin/serve public -s -p <port>
// For Node.js: ExecStart resolved via resolveExecStart from StartCommand.
func (p *Provisioner) writeSystemdUnit(siteID, username, docroot string, params NodeParams, port int) error {
	var execStart string
	if params.IsStatic {
		execStart = fmt.Sprintf("/usr/bin/serve public -s -p %d", port)
	} else {
		startCmd := params.StartCommand
		if startCmd == "" {
			startCmd = "server.js"
		}
		execStart = resolveExecStart(startCmd)
	}

	tmpl, err := template.New("unit").Parse(systemdUnitTemplate)
	if err != nil {
		return err
	}

	unitPath := fmt.Sprintf("/etc/systemd/system/%s", serviceUnit(siteID))
	f, err := os.OpenFile(unitPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("write unit %s: %w", unitPath, err)
	}
	defer f.Close()

	return tmpl.Execute(f, unitData{
		SiteID:    siteID,
		Username:  username,
		Docroot:   docroot,
		ExecStart: execStart,
	})
}

// serviceUnit returns the systemd unit file name for a site.
func serviceUnit(siteID string) string {
	return fmt.Sprintf("dnsfox-node-%s.service", siteID)
}

// allocatePort finds a free TCP port in [min, max].
func allocatePort(min, max int) (int, error) {
	for port := min; port <= max; port++ {
		ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err != nil {
			continue
		}
		ln.Close()
		return port, nil
	}
	return 0, fmt.Errorf("no free port in range %d-%d", min, max)
}

// cloneRepo clones a git repository into docroot as the site user.
func cloneRepo(ctx context.Context, repoURL, branch, docroot, username string) error {
	if branch == "" {
		branch = "main"
	}
	args := []string{"clone", "--depth", "1", "--branch", branch, "--", repoURL, docroot}
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Redact any token from error output.
		outStr := regexp.MustCompile(`://[^@\s]+@`).ReplaceAllString(string(out), "://***@")
		return fmt.Errorf("%w: %s", err, outStr)
	}
	// Strip .git to avoid credentials persisting in the volume.
	os.RemoveAll(docroot + "/.git") //nolint:errcheck
	exec.Command("chown", "-R", username+":"+username, docroot).Run() //nolint:errcheck
	return nil
}

// runAsUser runs a shell command in docroot as the site user via su.
func runAsUser(username, docroot, command string) error {
	cmd := exec.Command("su", "-s", "/bin/bash", "-c",
		fmt.Sprintf("cd %s && %s", docroot, command), username)
	cmd.Env = append(os.Environ(), "HOME=/var/www/"+username, "USER="+username)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

// parseDBCreds reads key=value pairs from the MariaDB credentials file.
func parseDBCreds(path string) (dbName, dbUser, dbPass string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return "", "", "", err
	}
	defer f.Close()

	vals := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, ";") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			vals[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return vals["DB_NAME"], vals["DB_USER"], vals["DB_PASS"], scanner.Err()
}

// validateParams checks that build/start commands are safe before execution.
func validateParams(p NodeParams) error {
	for _, cmd := range []string{p.StartCommand, p.BuildCommand} {
		if cmd != "" && !safeCmdPattern.MatchString(cmd) {
			return fmt.Errorf("command contains disallowed characters: %q", cmd)
		}
	}
	for k := range p.EnvVars {
		if !safeEnvKeyPattern.MatchString(k) {
			return fmt.Errorf("invalid env var key: %q", k)
		}
		if blockedEnvKeys[k] {
			return fmt.Errorf("env var %q is reserved and cannot be set", k)
		}
	}
	return nil
}

// waitForService waits for a systemd service to reach the active state.
// Non-fatal: caller logs any failure but continues.
func waitForService(svcName string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, _ := exec.Command("systemctl", "is-active", svcName).Output()
		if strings.TrimSpace(string(out)) == "active" {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service %s not active after %v", svcName, timeout)
}

// init avoids unused import error for time.
var _ = waitForService
