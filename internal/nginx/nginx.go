package nginx

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"text/template"
)

// Manager handles Nginx vhost config generation.
type Manager struct{}

// NewManager creates a new Nginx Manager.
func NewManager() *Manager {
	return &Manager{}
}

// VhostConfig holds the configuration for an Nginx vhost.
type VhostConfig struct {
	SiteID             string
	Domain             string
	Subdomain          string // e.g. "abc12345.sites.dnsfox.com"; added to server_name when set
	Username           string
	DocumentRoot       string
	PHPVersion         string
	EnableFastCGICache bool   // enable FastCGI page cache (opt-in; always off for Node.js)
	MaxUploadSize      string // nginx client_max_body_size, e.g. "64M"; defaults to "64M" if empty
}

// EffectiveMaxUploadSize returns MaxUploadSize, defaulting to "64M" when empty.
func (c VhostConfig) EffectiveMaxUploadSize() string {
	if c.MaxUploadSize != "" {
		return c.MaxUploadSize
	}
	return "64M"
}

// vhostTemplate generates an HTTP→HTTPS redirect block plus an HTTPS server block.
// Wildcard cert at /etc/ssl/dnsfox/wildcard-sites/ covers *.sites.dnsfox.com.
// X-Robots-Tag noindex prevents staging sites from being indexed.
// FastCGI page cache is opt-in via EnableFastCGICache; the V2_SITES zone must be
// declared in /etc/nginx/nginx.conf by the platform deployer before enabling.
const vhostTemplate = `# DNSFox v2 — auto-generated vhost for {{.Domain}}
# Do not edit manually — managed by Warden

server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}}{{if .Subdomain}} {{.Subdomain}}{{end}};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {{.Domain}}{{if .Subdomain}} {{.Subdomain}}{{end}};

    ssl_certificate     /etc/ssl/dnsfox/wildcard-sites/fullchain.pem;
    ssl_certificate_key /etc/ssl/dnsfox/wildcard-sites/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    root {{.DocumentRoot}};
    index index.php index.html;

    client_max_body_size {{.EffectiveMaxUploadSize}};
    client_body_timeout 300s;

    access_log /var/log/dnsfox/nginx-{{.SiteID}}-access.log;
    error_log  /var/log/dnsfox/nginx-{{.SiteID}}-error.log;

    add_header X-Robots-Tag "noindex, nofollow" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_pass unix:/run/php/{{.Username}}.sock;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        fastcgi_param HTTPS on;
        fastcgi_read_timeout 300;
        fastcgi_send_timeout 300;
        fastcgi_buffer_size 32k;
        fastcgi_buffers 16 16k;
        fastcgi_busy_buffers_size 64k;
        include fastcgi_params;
{{- if .EnableFastCGICache}}
        set $skip_cache 0;
        if ($request_method = POST)                                       { set $skip_cache 1; }
        if ($request_uri ~* "^(/cart|/checkout|/my-account)")            { set $skip_cache 1; }
        fastcgi_cache V2_SITES;
        fastcgi_cache_key "$scheme$request_method$host$request_uri";
        fastcgi_cache_valid 200 301 302 60m;
        fastcgi_cache_valid 404 1m;
        fastcgi_cache_lock on;
        fastcgi_cache_use_stale error timeout invalid_header http_500 http_503;
        fastcgi_cache_bypass $skip_cache
                             $cookie_wordpress_logged_in
                             $cookie_wordpress_sec
                             $cookie_comment_author
                             $cookie_woocommerce_cart_hash
                             $cookie_woocommerce_items_in_cart
                             $cookie_wp_woocommerce_session;
        fastcgi_no_cache    $skip_cache
                             $cookie_wordpress_logged_in
                             $cookie_wordpress_sec
                             $cookie_comment_author
                             $cookie_woocommerce_cart_hash
                             $cookie_woocommerce_items_in_cart
                             $cookie_wp_woocommerce_session;
        add_header X-Cache-Status $upstream_cache_status always;
{{- end}}
    }

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|webp|avif|svg|woff|woff2|ttf|eot|mp4|webm)$ {
        proxy_cache static_cache;
        proxy_cache_valid 200 30d;
        proxy_cache_key "$host$request_uri";
        proxy_cache_use_stale error timeout updating;
        proxy_cache_background_update on;
        proxy_cache_lock on;
        proxy_ignore_headers Cache-Control Set-Cookie;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header X-Cache-Status $upstream_cache_status always;
        access_log /var/log/nginx/cache-stats.log cache_stats;
    }

    # Cache purge — localhost only. Warden handles actual file removal via PurgeCache().
    location ~ ^/_purge(/.*)?$ {
        allow 127.0.0.1;
        deny all;
        return 200 "PURGED\n";
        add_header Content-Type text/plain;
    }

    location ~ /\. {
        deny all;
    }

    location ~* \.(env|log|sql|bak|credentials)$ {
        deny all;
    }
}
`

// vhostPath returns the path for the vhost config file.
// Uses conf.d-v2/ so v2 sites don't conflict with existing conf.d/ vhosts.
func vhostPath(siteID string) string {
	return fmt.Sprintf("/etc/nginx/conf.d-v2/dnsfox-%s.conf", siteID)
}

// WriteVhost writes an Nginx vhost config file for a site.
func (m *Manager) WriteVhost(cfg VhostConfig) error {
	if err := os.MkdirAll("/var/log/dnsfox", 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	tmpl, err := template.New("vhost").Parse(vhostTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	path := vhostPath(cfg.SiteID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create conf.d-v2 dir: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create vhost config: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, cfg); err != nil {
		return fmt.Errorf("render vhost template: %w", err)
	}

	// Validate config before caller reloads nginx.
	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		return fmt.Errorf("nginx -t failed after writing vhost: %s: %w", out, err)
	}
	return nil
}

// RemoveVhost removes the Nginx vhost config for a site.
func (m *Manager) RemoveVhost(siteID string) error {
	path := vhostPath(siteID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove vhost %s: %w", path, err)
	}
	return nil
}

// ProxyVhostConfig holds the configuration for a Node.js reverse-proxy vhost.
type ProxyVhostConfig struct {
	SiteID    string
	Domain    string
	Subdomain string // e.g. "abc12345.sites.dnsfox.com"; added to server_name when set
	Port      int    // localhost port the Node.js process listens on
}

const proxyVhostTemplate = `# DNSFox v2 — Node.js proxy vhost for {{.Domain}}
# Do not edit manually — managed by Warden

server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}}{{if .Subdomain}} {{.Subdomain}}{{end}};

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }
    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {{.Domain}}{{if .Subdomain}} {{.Subdomain}}{{end}};

    ssl_certificate     /etc/ssl/dnsfox/wildcard-sites/fullchain.pem;
    ssl_certificate_key /etc/ssl/dnsfox/wildcard-sites/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    access_log /var/log/dnsfox/nginx-{{.SiteID}}-access.log;
    error_log  /var/log/dnsfox/nginx-{{.SiteID}}-error.log;

    add_header X-Robots-Tag "noindex, nofollow" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Strict-Transport-Security "max-age=31536000" always;

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|webp|avif|svg|woff|woff2|ttf|eot|mp4|webm)$ {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache static_cache;
        proxy_cache_valid 200 30d;
        proxy_cache_key "$host$request_uri";
        proxy_cache_use_stale error timeout updating;
        proxy_cache_background_update on;
        proxy_cache_lock on;
        proxy_ignore_headers Cache-Control Set-Cookie;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header X-Cache-Status $upstream_cache_status always;
        access_log /var/log/nginx/cache-stats.log cache_stats;
    }

    location / {
        proxy_pass http://127.0.0.1:{{.Port}};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
    }

    location ~ /\. {
        deny all;
    }
}
`

// WriteProxyVhost writes an Nginx reverse-proxy vhost for a Node.js site.
// Validates config with nginx -t before returning.
func (m *Manager) WriteProxyVhost(cfg ProxyVhostConfig) error {
	if err := os.MkdirAll("/var/log/dnsfox", 0755); err != nil {
		return fmt.Errorf("create log dir: %w", err)
	}

	tmpl, err := template.New("proxy-vhost").Parse(proxyVhostTemplate)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	path := vhostPath(cfg.SiteID)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create conf.d-v2 dir: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create proxy vhost: %w", err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, cfg); err != nil {
		return fmt.Errorf("render proxy vhost: %w", err)
	}

	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		return fmt.Errorf("nginx -t failed: %s: %w", out, err)
	}
	return nil
}

// PurgeCache removes cached responses for a site. url is optional; when empty
// the entire per-site cache directory is wiped. Returns the number of files removed.
// The nginx proxy_cache_path for v2 sites lives at /var/cache/nginx/v2-sites/{siteID}/.
func (m *Manager) PurgeCache(siteID, url string) (int32, error) {
	cacheDir := filepath.Join("/var/cache/nginx/v2-sites", siteID)
	entries, err := os.ReadDir(cacheDir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("read cache dir: %w", err)
	}
	var count int32
	for _, e := range entries {
		if err := os.RemoveAll(filepath.Join(cacheDir, e.Name())); err == nil {
			count++
		}
	}
	return count, nil
}

// ─── CDN Edge Vhost ──────────────────────────────────────────────────────────

// EdgeVhostConfig holds the configuration for a CDN edge reverse-proxy vhost.
// The edge proxies all traffic to OriginIP, caching static assets for 30 days
// and dynamic pages for 1 hour (with cookie-based bypass for logged-in users).
type EdgeVhostConfig struct {
	SiteID    string
	Domain    string
	OriginIP  string // IP of the origin server (the VPS hosting the actual site)
	HasWWW    bool   // whether to also serve www.{Domain}
}

// edgeVhostPath returns the path for the edge vhost config.
// Stored in sites-enabled so it can coexist with conf.d-v2/ origin configs.
func edgeVhostPath(domain string) string {
	return fmt.Sprintf("/etc/nginx/sites-enabled/%s", domain)
}

const edgeVhostTemplate = `# DNSFox CDN edge vhost for {{.Domain}} → origin {{.OriginIP}}
# Managed by Warden — do not edit manually

server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}}{{if .HasWWW}} www.{{.Domain}}{{end}};
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl;
    listen [::]:443 ssl;
    http2 on;
    server_name {{.Domain}}{{if .HasWWW}} www.{{.Domain}}{{end}};

    ssl_certificate     /etc/ssl/dnsfox/{{.Domain}}/fullchain.pem;
    ssl_certificate_key /etc/ssl/dnsfox/{{.Domain}}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL_EDGE:10m;

    # Pass real client IP to origin.
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto https;

    # Origin connection — our own server; skip cert verification.
    proxy_ssl_verify     off;
    proxy_ssl_server_name on;

    # Cache bypass: skip for admin, checkout, POST, and session cookies.
    set $skip_cache 0;
    if ($request_method = POST)                                                { set $skip_cache 1; }
    if ($request_uri ~* "^/(wp-admin|wp-login\.php|cart|checkout|my-account)") { set $skip_cache 1; }
    if ($cookie_wordpress_logged_in)                                            { set $skip_cache 1; }
    if ($cookie_woocommerce_cart_hash)                                          { set $skip_cache 1; }

    # Static assets — 30-day edge cache, immutable.
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|webp|avif|svg|woff|woff2|ttf|eot|mp4|webm)$ {
        proxy_pass https://{{.OriginIP}};
        proxy_cache         static_cache;
        proxy_cache_valid   200 30d;
        proxy_cache_key     "$host$request_uri";
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_background_update on;
        proxy_cache_lock    on;
        proxy_ignore_headers Cache-Control Set-Cookie;
        proxy_cache_bypass  0;
        proxy_no_cache      0;
        add_header Cache-Control "public, max-age=31536000, immutable" always;
        add_header X-Cache-Status $upstream_cache_status always;
        add_header X-Edge-Server  $hostname always;
        access_log /var/log/nginx/cache-stats.log cache_stats;
    }

    # Everything else — 1-hour edge cache with session bypass.
    location / {
        proxy_pass https://{{.OriginIP}};
        proxy_cache         static_cache;
        proxy_cache_valid   200 301 302 1h;
        proxy_cache_valid   404 1m;
        proxy_cache_key     "$host$request_uri";
        proxy_cache_use_stale error timeout updating http_500 http_502 http_503 http_504;
        proxy_cache_background_update on;
        proxy_cache_lock    on;
        proxy_cache_bypass  $skip_cache;
        proxy_no_cache      $skip_cache;
        proxy_read_timeout  30;
        proxy_connect_timeout 10;
        add_header X-Cache-Status $upstream_cache_status always;
        add_header X-Edge-Server  $hostname always;
        access_log /var/log/nginx/cache-stats.log cache_stats;
    }

    location ~ /\. { deny all; }
}
`

// WriteEdgeVhost writes a CDN edge reverse-proxy vhost config for a domain.
// The SSL cert must already be installed at /etc/ssl/dnsfox/{domain}/.
func (m *Manager) WriteEdgeVhost(cfg EdgeVhostConfig) error {
	tmpl, err := template.New("edge-vhost").Parse(edgeVhostTemplate)
	if err != nil {
		return fmt.Errorf("edge vhost: parse template: %w", err)
	}

	path := edgeVhostPath(cfg.Domain)
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("edge vhost: create %s: %w", path, err)
	}
	defer f.Close()

	if err := tmpl.Execute(f, cfg); err != nil {
		return fmt.Errorf("edge vhost: render: %w", err)
	}

	if out, err := exec.Command("nginx", "-t").CombinedOutput(); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("edge vhost: nginx -t failed: %s: %w", out, err)
	}
	return nil
}

// RemoveEdgeVhost deletes the CDN edge vhost config for a domain.
func (m *Manager) RemoveEdgeVhost(domain string) error {
	path := edgeVhostPath(domain)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("edge vhost: remove %s: %w", path, err)
	}
	return nil
}
