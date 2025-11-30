package substack

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"standard", "https://username.substack.com", true},
		{"with path", "https://username.substack.com/about", true},
		{"no protocol", "username.substack.com", true},
		{"custom domain", "https://newsletter.com", false},
		{"other domain", "https://medium.com/@user", false},
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
		{"standard", "https://newsletter.substack.com", "newsletter"},
		{"with path", "https://johndoe.substack.com/p/post", "johndoe"},
		{"no protocol", "username.substack.com", "username"},
		{"invalid", "https://substack.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
