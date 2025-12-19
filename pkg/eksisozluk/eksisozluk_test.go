package eksisozluk

import (
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{
			name: "valid profile URL",
			url:  "https://eksisozluk.com/biri/prototip-proto",
			want: true,
		},
		{
			name: "valid profile URL with www",
			url:  "https://www.eksisozluk.com/biri/zzg",
			want: true,
		},
		{
			name: "valid profile URL with trailing slash",
			url:  "https://eksisozluk.com/biri/asik-pozisyonu/",
			want: true,
		},
		{
			name: "entry URL (not profile)",
			url:  "https://eksisozluk.com/entry/12345",
			want: false,
		},
		{
			name: "topic URL (not profile)",
			url:  "https://eksisozluk.com/yazilim--52825",
			want: false,
		},
		{
			name: "different domain",
			url:  "https://example.com/biri/username",
			want: false,
		},
		{
			name: "empty URL",
			url:  "",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "basic profile URL",
			url:  "https://eksisozluk.com/biri/prototip-proto",
			want: "prototip-proto",
		},
		{
			name: "profile URL with trailing slash",
			url:  "https://eksisozluk.com/biri/zzg/",
			want: "zzg",
		},
		{
			name: "profile URL with query params",
			url:  "https://eksisozluk.com/biri/username?tab=entries",
			want: "username",
		},
		{
			name: "invalid URL",
			url:  "https://eksisozluk.com/entry/12345",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("AuthRequired() should return false for public profiles")
	}
}
