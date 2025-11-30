package reddit

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"user path", "https://reddit.com/user/username", true},
		{"u path", "https://reddit.com/u/username", true},
		{"old reddit", "https://old.reddit.com/user/username", true},
		{"www reddit", "https://www.reddit.com/user/username", true},
		{"subreddit", "https://reddit.com/r/golang", false},
		{"other domain", "https://twitter.com/user", false},
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
		{"user path", "https://reddit.com/user/johndoe", "johndoe"},
		{"u path", "https://reddit.com/u/johndoe", "johndoe"},
		{"with trailing slash", "https://reddit.com/user/johndoe/", "johndoe"},
		{"old reddit", "https://old.reddit.com/user/username", "username"},
		{"invalid", "https://reddit.com/r/golang", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
