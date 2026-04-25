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
	SiteID            string
	Domain            string
	Subdomain         string // e.g. "abc12345.sites.dnsfox.com"; added to server_name when set
	Username          string
	DocumentRoot      string
	PHPVersion        string
	EnableFastCGICache bool   // enable FastCGI page cache (opt-in; always off for Node.js)
	MaxUploadSize     string  // nginx client_max_body_size, e.g. "64M"; defaults to "64M" if empty
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

    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        expires 7d;
        add_header Cache-Control "public, no-transform";
        access_log off;
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
