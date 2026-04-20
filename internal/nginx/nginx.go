package nginx

import (
	"fmt"
	"os"
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
	SiteID       string
	Domain       string
	Username     string
	DocumentRoot string
	PHPVersion   string
}

// vhostTemplate is the Nginx vhost config template.
const vhostTemplate = `# DNSFox v2 — auto-generated vhost for {{.Domain}}
# Do not edit manually — managed by Warden

server {
    listen 80;
    listen [::]:80;
    server_name {{.Domain}} www.{{.Domain}};

    root {{.DocumentRoot}};
    index index.php index.html;

    # Logs per site
    access_log /var/log/dnsfox/nginx-{{.SiteID}}-access.log;
    error_log  /var/log/dnsfox/nginx-{{.SiteID}}-error.log;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        try_files $uri $uri/ /index.php?$args;
    }

    location ~ \.php$ {
        try_files $uri =404;
        fastcgi_split_path_info ^(.+\.php)(/.+)$;
        fastcgi_pass unix:/run/php/{{.Username}}.sock;
        fastcgi_index index.php;
        fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include fastcgi_params;
        fastcgi_read_timeout 300;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
    }

    # Deny access to sensitive files
    location ~* \.(env|log|sql|bak)$ {
        deny all;
    }
}
`

// vhostPath returns the path for the vhost config file.
func vhostPath(siteID string) string {
	return fmt.Sprintf("/etc/nginx/conf.d/dnsfox-%s.conf", siteID)
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
		return fmt.Errorf("create conf.d dir: %w", err)
	}

	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create vhost config: %w", err)
	}
	defer f.Close()

	return tmpl.Execute(f, cfg)
}

// RemoveVhost removes the Nginx vhost config for a site.
func (m *Manager) RemoveVhost(siteID string) error {
	path := vhostPath(siteID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove vhost %s: %w", path, err)
	}
	return nil
}
