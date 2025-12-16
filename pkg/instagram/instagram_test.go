package instagram

import (
	"context"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://instagram.com/johndoe", true},
		{"https://www.instagram.com/johndoe", true},
		{"https://INSTAGRAM.COM/johndoe", true},
		{"https://instagram.com/p/ABC123", false},     // post URL
		{"https://instagram.com/reel/ABC123", false},  // reel URL
		{"https://instagram.com/stories/user", false}, // stories URL
		{"https://instagram.com/explore", false},      // explore page
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

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://instagram.com/johndoe", "johndoe"},
		{"https://www.instagram.com/jane_doe", "jane_doe"},
		{"https://instagram.com/user.name", "user.name"},
		{"https://instagram.com/p/ABC123", ""},
		{"https://instagram.com/reel/ABC123", ""},
		{"https://instagram.com/explore", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractUsername(tt.url)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestNewClient(t *testing.T) {
	client, err := New(context.Background())
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	if client == nil {
		t.Error("New() returned nil client")
	}
}
