package provisioning

import (
	"testing"
)

func TestSiteUsername(t *testing.T) {
	tests := []struct {
		siteID   string
		expected string
	}{
		{"abc123", "site_abc123"},
		{"verylongsiteid12345", "site_verylongsiteid1"},
		{"x", "site_x"},
	}
	for _, tt := range tests {
		got := siteUsername(tt.siteID)
		if got != tt.expected {
			t.Errorf("siteUsername(%q) = %q, want %q", tt.siteID, got, tt.expected)
		}
	}
}

func TestPlanMaxChildren(t *testing.T) {
	tests := []struct {
		plan     string
		expected int
	}{
		{"fox", 5},
		{"swift", 10},
		{"apex", 20},
		{"titan", 40},
		{"unknown", 5},
	}
	for _, tt := range tests {
		got := planMaxChildren(tt.plan)
		if got != tt.expected {
			t.Errorf("planMaxChildren(%q) = %d, want %d", tt.plan, got, tt.expected)
		}
	}
}

func TestPlanIsSmall(t *testing.T) {
	tests := []struct {
		plan     string
		expected bool
	}{
		{"fox", true},
		{"swift", false},
		{"apex", false},
		{"titan", false},
		{"unknown", false},
	}
	for _, tt := range tests {
		got := planIsSmall(tt.plan)
		if got != tt.expected {
			t.Errorf("planIsSmall(%q) = %v, want %v", tt.plan, got, tt.expected)
		}
	}
}

func TestPlanLimits(t *testing.T) {
	plans := []string{"fox", "swift", "apex", "titan"}
	for _, plan := range plans {
		limits, ok := PlanLimits[plan]
		if !ok {
			t.Errorf("PlanLimits missing plan %q", plan)
			continue
		}
		if limits.CPUPercent <= 0 {
			t.Errorf("plan %q has invalid CPUPercent %d", plan, limits.CPUPercent)
		}
		if limits.RAMMb <= 0 {
			t.Errorf("plan %q has invalid RAMMb %d", plan, limits.RAMMb)
		}
	}
}
