package fourprogrammers

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
			url:  "https://4programmers.net/Profile/83383",
			want: true,
		},
		{
			name: "valid profile URL with www",
			url:  "https://www.4programmers.net/Profile/12345",
			want: true,
		},
		{
			name: "valid profile URL with trailing slash",
			url:  "https://4programmers.net/Profile/83383/",
			want: true,
		},
		{
			name: "forum URL (not profile)",
			url:  "https://4programmers.net/Forum/PHP",
			want: false,
		},
		{
			name: "job URL (not profile)",
			url:  "https://4programmers.net/Praca",
			want: false,
		},
		{
			name: "different domain",
			url:  "https://example.com/Profile/123",
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

func TestExtractUserID(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{
			name: "basic profile URL",
			url:  "https://4programmers.net/Profile/83383",
			want: "83383",
		},
		{
			name: "profile URL with trailing slash",
			url:  "https://4programmers.net/Profile/12345/",
			want: "12345",
		},
		{
			name: "profile URL with query params",
			url:  "https://4programmers.net/Profile/83383?tab=posts",
			want: "83383",
		},
		{
			name: "invalid URL",
			url:  "https://4programmers.net/Forum/PHP",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUserID(tt.url); got != tt.want {
				t.Errorf("extractUserID(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("AuthRequired() should return false for public profiles")
	}
}
