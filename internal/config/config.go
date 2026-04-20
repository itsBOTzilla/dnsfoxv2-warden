// Package config loads Warden v2 configuration from environment variables
// with sensible defaults. All config is read at startup — no file watching
// or hot reload.
package config

import (
	"fmt"
	"os"
)

// Config holds all runtime configuration for the v2 Warden agent.
type Config struct {
	ServerID      string
	GRPCPort      string
	Environment   string
	MariaDBHost   string
	MariaDBPort   string
	MariaDBRootPw string
	RedisHost     string
	RedisPort     string
	NginxVhostDir string
	WildcardCert  string
	WildcardKey   string
	CgroupSlice   string
	DocrootBase   string
	LogDir        string
	SitesDomain   string
}

// Load reads config from WARDEN_* environment variables and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{
		ServerID:      getEnv("WARDEN_SERVER_ID", ""),
		GRPCPort:      getEnv("WARDEN_GRPC_PORT", "9201"),
		Environment:   getEnv("WARDEN_ENVIRONMENT", "production"),
		MariaDBHost:   getEnv("WARDEN_MARIADB_HOST", "127.0.0.1"),
		MariaDBPort:   getEnv("WARDEN_MARIADB_PORT", "3307"),
		MariaDBRootPw: getEnv("MARIADB_ROOT_PASSWORD", ""),
		RedisHost:     getEnv("WARDEN_REDIS_HOST", "127.0.0.1"),
		RedisPort:     getEnv("WARDEN_REDIS_PORT", "6380"),
		NginxVhostDir: getEnv("WARDEN_NGINX_VHOST_DIR", "/etc/nginx/conf.d-v2"),
		WildcardCert:  getEnv("WARDEN_WILDCARD_CERT", "/etc/ssl/dnsfox/wildcard-sites/fullchain.pem"),
		WildcardKey:   getEnv("WARDEN_WILDCARD_KEY", "/etc/ssl/dnsfox/wildcard-sites/privkey.pem"),
		CgroupSlice:   getEnv("WARDEN_CGROUP_SLICE", "dnsfox-sites.slice"),
		DocrootBase:   getEnv("WARDEN_DOCROOT_BASE", "/var/www"),
		LogDir:        getEnv("WARDEN_LOG_DIR", "/var/log/dnsfox"),
		SitesDomain:   getEnv("WARDEN_SITES_DOMAIN", "sites.dnsfox.com"),
	}

	if cfg.ServerID == "" {
		return nil, fmt.Errorf("WARDEN_SERVER_ID is required but not set")
	}

	return cfg, nil
}

// getEnv returns the value of the named env var, or defaultVal if unset or empty.
func getEnv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}
