package habr

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"modern habr.com", "https://habr.com/ru/users/rock", true},
		{"english habr.com", "https://habr.com/en/users/rock", true},
		{"old habrahabr.ru", "http://habrahabr.ru/users/rock", true},
		{"with trailing slash", "https://habr.com/ru/users/rock/", true},
		{"non-profile habr", "https://habr.com/ru/articles/", false},
		{"other domain", "https://example.com/users/rock", false},
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
		{"modern habr", "https://habr.com/ru/users/rock", "rock"},
		{"old habrahabr", "http://habrahabr.ru/users/rock", "rock"},
		{"english habr", "https://habr.com/en/users/someuser", "someuser"},
		{"with trailing slash", "https://habr.com/ru/users/rock/", "rock"},
		{"invalid", "https://habr.com/articles/", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
