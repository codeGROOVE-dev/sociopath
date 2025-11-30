package instagram

import (
	"context"
	"errors"
	"testing"

	"github.com/codeGROOVE-dev/sociopath/profile"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://instagram.com/johndoe", true},
		{"https://www.instagram.com/johndoe", true},
		{"https://INSTAGRAM.COM/johndoe", true},
		{"https://twitter.com/johndoe", false},
		{"https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := Match(tt.url)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if !AuthRequired() {
		t.Error("Instagram should require auth")
	}
}

func TestNewWithoutCookies(t *testing.T) {
	_, err := New(context.Background())
	if err == nil {
		t.Error("New() without cookies should fail")
	}
	if !errors.Is(err, profile.ErrAuthRequired) {
		t.Errorf("error should wrap ErrAuthRequired, got: %v", err)
	}
}
