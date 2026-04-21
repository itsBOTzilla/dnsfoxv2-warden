// helpers.go — shared helpers for WordPress / PHP converters.
// Functions here are used by wordpress.go and php.go; nodejs.go predates
// them and keeps its own local copies.
package v1convert

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// mysqldumpFromContainer runs mysqldump inside a MariaDB docker container and
// writes a gzipped dump to dstPath. Uses --single-transaction + --quick to
// produce a consistent snapshot without locking the whole DB.
//
// Credentials are read from the container's environment (MARIADB_ROOT_PASSWORD
// or MYSQL_ROOT_PASSWORD); we never need to know them on the host.
func mysqldumpFromContainer(ctx context.Context, container, dstPath string) error {
	pw, err := containerEnv(ctx, container, []string{"MARIADB_ROOT_PASSWORD", "MYSQL_ROOT_PASSWORD"})
	if err != nil {
		return fmt.Errorf("find root password in %s env: %w", container, err)
	}
	dumpCmd := fmt.Sprintf(
		`mysqldump -uroot -p%q --all-databases --single-transaction --quick --routines --triggers | gzip -c`,
		pw,
	)
	f, err := os.OpenFile(dstPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("open dst: %w", err)
	}
	defer f.Close()

	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container, "sh", "-c", dumpCmd)
	cmd.Stdout = f
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("mysqldump: %w: %s", err, stderr.String())
	}
	return nil
}

// containerEnv reads the container's config env (same slice docker inspect
// returns) and returns the first value matching any of the given keys. Returns
// error if none match.
func containerEnv(ctx context.Context, container string, keys []string) (string, error) {
	info, err := inspectContainer(ctx, container)
	if err != nil {
		return "", err
	}
	for _, kv := range info.Env {
		idx := strings.IndexByte(kv, '=')
		if idx <= 0 {
			continue
		}
		k := kv[:idx]
		for _, want := range keys {
			if k == want {
				return kv[idx+1:], nil
			}
		}
	}
	return "", fmt.Errorf("no env var in %v", keys)
}

// importSQLDump gunzips + pipes a mysqldump file into host MariaDB on
// 127.0.0.1:3307, selecting database dbName.  Uses the admin credentials
// that mariadb.Manager uses — read from MARIADB_ROOT_USER/PASSWORD env.
func importSQLDump(ctx context.Context, srcGz, dbName string) error {
	rootUser := os.Getenv("MARIADB_ROOT_USER")
	if rootUser == "" {
		rootUser = "root"
	}
	rootPass := os.Getenv("MARIADB_ROOT_PASSWORD")

	f, err := os.Open(srcGz)
	if err != nil {
		return fmt.Errorf("open dump: %w", err)
	}
	defer f.Close()

	// gunzip | mysql. We pipe via sh -c so the shell handles decompression.
	args := []string{"-h", "127.0.0.1", "-P", "3307", "-u", rootUser}
	if rootPass != "" {
		args = append(args, "-p"+rootPass)
	}
	args = append(args, dbName)

	shellCmd := fmt.Sprintf("gunzip -c | mysql %s", joinArgs(args))
	cmd := exec.CommandContext(ctx, "sh", "-c", shellCmd)
	cmd.Stdin = f
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("mysql import: %w: %s", err, out)
	}
	return nil
}

// joinArgs joins args with spaces and shell-quotes only the password so it
// survives special characters.  All other args are known-safe (host/port/user).
func joinArgs(args []string) string {
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if strings.HasPrefix(a, "-p") {
			b.WriteString("-p")
			b.WriteByte('\'')
			b.WriteString(strings.ReplaceAll(a[2:], "'", "'\\''"))
			b.WriteByte('\'')
		} else {
			b.WriteString(a)
		}
	}
	return b.String()
}

// waitForFile polls for a file to exist, up to maxAttempts × 250ms.
func waitForFile(path string, maxAttempts int) error {
	for i := 0; i < maxAttempts; i++ {
		if _, err := os.Stat(path); err == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("file %s not ready after %d attempts", path, maxAttempts)
}

// reloadPHPFPMVersion reloads the PHP-FPM systemd service for a version.
// Matches the naming convention in provisioning/provisioning.go.
func reloadPHPFPMVersion(ctx context.Context, version string) error {
	svc := fmt.Sprintf("php%s-fpm-dnsfox", version)
	if version == "8.4" {
		svc = "php8.4-fpm"
	}
	_, err := runCmd(ctx, "systemctl", "reload", svc)
	return err
}

// waitForHTTPHost issues HTTP GETs with a Host header against 127.0.0.1:80
// until a non-5xx response comes back or the timeout expires.  Used as the
// post-swap health check for PHP / WordPress sites where the v2 nginx vhost
// is already in place.
func waitForHTTPHost(ctx context.Context, domain string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	client := &http.Client{
		Timeout: 3 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			// Accept any redirect (HTTP→HTTPS is normal for v2 vhost).
			return http.ErrUseLastResponse
		},
	}
	var lastErr error
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		req, err := http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/", nil)
		if err != nil {
			return err
		}
		req.Host = domain
		resp, err := client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode < 500 {
				return nil
			}
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
		} else {
			lastErr = err
		}
		time.Sleep(500 * time.Millisecond)
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("timeout after %v", timeout)
	}
	return lastErr
}

// wpConfigRewrites define the DB_* define() lines we need to update.
var (
	wpDBNameRE = regexp.MustCompile(`(?m)^(\s*define\s*\(\s*['"]DB_NAME['"]\s*,\s*)['"][^'"]*['"](\s*\)\s*;)`)
	wpDBUserRE = regexp.MustCompile(`(?m)^(\s*define\s*\(\s*['"]DB_USER['"]\s*,\s*)['"][^'"]*['"](\s*\)\s*;)`)
	wpDBPassRE = regexp.MustCompile(`(?m)^(\s*define\s*\(\s*['"]DB_PASSWORD['"]\s*,\s*)['"][^'"]*['"](\s*\)\s*;)`)
	wpDBHostRE = regexp.MustCompile(`(?m)^(\s*define\s*\(\s*['"]DB_HOST['"]\s*,\s*)['"][^'"]*['"](\s*\)\s*;)`)
)

// rewriteWPConfig edits wp-config.php in place to point at the new host
// MariaDB credentials. Keeps all other defines (table prefix, salts, etc.)
// intact. File permission is restored to 0440 afterwards.
func rewriteWPConfig(path string, c *dbCreds) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read: %w", err)
	}
	host := fmt.Sprintf("%s:%s", c.Host, c.Port)
	out := wpDBNameRE.ReplaceAll(data, []byte(`${1}'`+c.Name+`'${2}`))
	out = wpDBUserRE.ReplaceAll(out, []byte(`${1}'`+c.User+`'${2}`))
	out = wpDBPassRE.ReplaceAll(out, []byte(`${1}'`+escapePHPSingle(c.Pass)+`'${2}`))
	out = wpDBHostRE.ReplaceAll(out, []byte(`${1}'`+host+`'${2}`))
	if err := os.WriteFile(path, out, 0o640); err != nil {
		return fmt.Errorf("write: %w", err)
	}
	_ = os.Chmod(path, 0o440)
	return nil
}

// escapePHPSingle escapes a string for embedding inside PHP single quotes.
func escapePHPSingle(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`)
}

