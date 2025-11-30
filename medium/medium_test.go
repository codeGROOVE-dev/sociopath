package medium

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"standard profile", "https://medium.com/@username", true},
		{"no protocol", "medium.com/@username", true},
		{"with path", "https://medium.com/@username/article-title", true},
		{"user path", "https://medium.com/user/username", true},
		{"non-profile", "https://medium.com/publication", false},
		{"other domain", "https://twitter.com/@username", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("AuthRequired() = true, want false")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"standard", "https://medium.com/@kentcdodds", "kentcdodds"},
		{"no protocol", "medium.com/@username", "username"},
		{"with article", "https://medium.com/@user/article-123", "user"},
		{"user path", "https://medium.com/user/johndoe", "johndoe"},
		{"invalid", "https://medium.com/publication", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
