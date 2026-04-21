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
	RedisPassword string
	NginxVhostDir string
	WildcardCert  string
	WildcardKey   string
	CgroupSlice   string
	DocrootBase   string
	LogDir        string
	SitesDomain   string
	// APIUrl is the base URL of the v2 control-plane API.
	// The heartbeat loop sends metrics here and receives jobs.
	APIUrl string
	// APIToken authenticates requests to the v2 control-plane API
	// (mu-plugin downloads, job result reports, etc.).
	APIToken string
	// SMTPRelaySecret is used with HMAC-SHA256 to derive per-site SMTP passwords
	// for the relay.dnsfox.com relay. Empty = SMTP not configured.
	SMTPRelaySecret string
	// PayloadEncryptionKey is the hex-encoded AES-256 key used to decrypt
	// AgentJob.encrypted_payload fields delivered via heartbeat.
	PayloadEncryptionKey string
	// InternalToken is a shared secret the v2 API presents on Authorization
	// when calling privileged warden endpoints (file manager upload, etc.).
	// When empty, privileged HTTP endpoints return 401 unauthorized.
	InternalToken string
}

// Load reads config from WARDEN_* environment variables and validates required fields.
func Load() (*Config, error) {
	cfg := &Config{
		ServerID:        getEnv("WARDEN_SERVER_ID", ""),
		GRPCPort:        getEnv("WARDEN_GRPC_PORT", "9201"),
		Environment:     getEnv("WARDEN_ENVIRONMENT", "production"),
		MariaDBHost:     getEnv("WARDEN_MARIADB_HOST", "127.0.0.1"),
		MariaDBPort:     getEnv("WARDEN_MARIADB_PORT", "3307"),
		MariaDBRootPw:   getEnv("MARIADB_ROOT_PASSWORD", ""),
		RedisHost:       getEnv("WARDEN_REDIS_HOST", "127.0.0.1"),
		RedisPort:       getEnv("WARDEN_REDIS_PORT", "6380"),
		RedisPassword:   getEnv("WARDEN_REDIS_PASSWORD", ""),
		NginxVhostDir:   getEnv("WARDEN_NGINX_VHOST_DIR", "/etc/nginx/conf.d-v2"),
		WildcardCert:    getEnv("WARDEN_WILDCARD_CERT", "/etc/ssl/dnsfox/wildcard-sites/fullchain.pem"),
		WildcardKey:     getEnv("WARDEN_WILDCARD_KEY", "/etc/ssl/dnsfox/wildcard-sites/privkey.pem"),
		CgroupSlice:     getEnv("WARDEN_CGROUP_SLICE", "dnsfox-sites.slice"),
		DocrootBase:     getEnv("WARDEN_DOCROOT_BASE", "/var/www"),
		LogDir:          getEnv("WARDEN_LOG_DIR", "/var/log/dnsfox"),
		SitesDomain:     getEnv("WARDEN_SITES_DOMAIN", "sites.dnsfox.com"),
		APIUrl:          getEnv("WARDEN_API_URL", "http://127.0.0.1:5000"),
		APIToken:             getEnv("WARDEN_API_TOKEN", ""),
		SMTPRelaySecret:      getEnv("WARDEN_SMTP_RELAY_SECRET", ""),
		PayloadEncryptionKey: getEnv("WARDEN_PAYLOAD_ENCRYPTION_KEY", ""),
		InternalToken:        getEnv("WARDEN_INTERNAL_TOKEN", ""),
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
