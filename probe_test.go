package fail2ban

import (
	"net/http/httptest"
	"testing"
)

func TestIsProbe(t *testing.T) {
	extra := probePrefixes([]string{"/old-admin"})
	tests := []struct {
		path string
		want bool
	}{
		{"/.env", true},
		{"/.ENV", true},
		{"/.git/config", true},
		{"/wp-admin/x", true},
		{"/vendor/phpunit/src", true},
		{"/old-admin", true},
		{"/OLD-ADMIN/users", true},
		{"/.envoy", true}, // a plain prefix match, as the README says
		{"/environment", false},
		{"/", false},
		{"/blog/wp-admin", false},
		{"/.git", true},
		{"/x/.git", true},
		{"/api/.env", true},
		{"/API/.ENV", true},
		{"/backend/.git/config", true},
		{"/a/b/.git/HEAD", true},
		{"/.github", false},
		{"/blog/.gitignore-tips", false},
		{"/api/.env.local", true},
		{"/api/.envoy", true}, // as at the root, a segment starting with ".env"
		{"/api/x.env", false},
		{"/x/.gitconfig", false},
		{"/docs/env", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.path, nil)
			if got := isProbe(r, extra); got != tt.want {
				t.Errorf("isProbe(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

// An empty ProbePaths entry would make every path a probe; it is skipped.
func TestProbePrefixes_SkipsEmpty(t *testing.T) {
	r := httptest.NewRequest("GET", "/about", nil)
	if isProbe(r, probePrefixes([]string{""})) {
		t.Error("an empty ProbePaths entry made /about a probe")
	}
}

func TestIsEarlyRejection(t *testing.T) {
	tests := []struct {
		target string
		want   bool
	}{
		{"/x%2fy", true},
		{"/x%2Fy", true},
		{"/a%2f..%2fb", true},
		{"/a/./b", true},
		{"/a/../b", true},
		{"/..", true},
		{"/a/.", true},
		{"/blog//post", false}, // a sloppy link a reader follows, not a probe
		{"/blog/post/", false},
		{"/.env", false}, // a probe, but by its prefix, not as an early rejection
		{"/a/..b/c", false},
		{"/", false},
	}
	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.target, nil)
			if got := isEarlyRejection(r); got != tt.want {
				t.Errorf("isEarlyRejection(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}
