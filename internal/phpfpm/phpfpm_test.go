package phpfpm

import (
	"bytes"
	"strings"
	"testing"
	"text/template"
)

func renderSiteConfig(cfg PoolConfig) (string, error) {
	tmpl, err := template.New("sitecfg").Parse(siteConfigTemplate)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, cfg); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func TestSiteConfigTemplate_Dynamic(t *testing.T) {
	cfg := PoolConfig{
		SiteID:      "abc123",
		Username:    "site_abc123",
		PHPVersion:  "8.3",
		MaxChildren: 10,
		Ondemand:    false,
	}
	out, err := renderSiteConfig(cfg)
	if err != nil {
		t.Fatalf("template error: %v", err)
	}

	checks := []string{
		"pm = dynamic",
		"pm.max_children = 10",
		"pm.start_servers = 2",
		"pm.min_spare_servers = 1",
		"pm.max_spare_servers = 3",
		"pm.max_requests = 500",
	}
	for _, s := range checks {
		if !strings.Contains(out, s) {
			t.Errorf("dynamic config missing %q", s)
		}
	}
	if strings.Contains(out, "pm = ondemand") {
		t.Error("dynamic config must not contain pm = ondemand")
	}
	if strings.Contains(out, "pm.process_idle_timeout") {
		t.Error("dynamic config must not contain pm.process_idle_timeout")
	}
}

func TestSiteConfigTemplate_Ondemand(t *testing.T) {
	cfg := PoolConfig{
		SiteID:      "abc123",
		Username:    "site_abc123",
		PHPVersion:  "8.3",
		MaxChildren: 5,
		Ondemand:    true,
	}
	out, err := renderSiteConfig(cfg)
	if err != nil {
		t.Fatalf("template error: %v", err)
	}

	checks := []string{
		"pm = ondemand",
		"pm.max_children = 5",
		"pm.process_idle_timeout = 60s",
		"pm.max_requests = 500",
	}
	for _, s := range checks {
		if !strings.Contains(out, s) {
			t.Errorf("ondemand config missing %q", s)
		}
	}
	if strings.Contains(out, "pm = dynamic") {
		t.Error("ondemand config must not contain pm = dynamic")
	}
	if strings.Contains(out, "pm.start_servers") {
		t.Error("ondemand config must not contain pm.start_servers")
	}
}
