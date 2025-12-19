package wykop

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
			url:  "https://wykop.pl/ludzie/wykop",
			want: true,
		},
		{
			name: "valid profile URL with www",
			url:  "https://www.wykop.pl/ludzie/lurker",
			want: true,
		},
		{
			name: "valid profile URL with trailing slash",
			url:  "https://wykop.pl/ludzie/username/",
			want: true,
		},
		{
			name: "entry URL (not profile)",
			url:  "https://wykop.pl/wpis/12345",
			want: false,
		},
		{
			name: "link URL (not profile)",
			url:  "https://wykop.pl/link/67890",
			want: false,
		},
		{
			name: "tag URL (not profile)",
			url:  "https://wykop.pl/tag/programowanie",
			want: false,
		},
		{
			name: "different domain",
			url:  "https://example.com/ludzie/username",
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
			url:  "https://wykop.pl/ludzie/wykop",
			want: "wykop",
		},
		{
			name: "profile URL with trailing slash",
			url:  "https://wykop.pl/ludzie/lurker/",
			want: "lurker",
		},
		{
			name: "profile URL with query params",
			url:  "https://wykop.pl/ludzie/username?tab=entries",
			want: "username",
		},
		{
			name: "username with hyphen",
			url:  "https://wykop.pl/ludzie/user-name",
			want: "user-name",
		},
		{
			name: "invalid URL",
			url:  "https://wykop.pl/wpis/12345",
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
