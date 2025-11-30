package weibo

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"user ID", "https://weibo.com/u/1234567", true},
		{"username", "https://weibo.com/username", true},
		{"numeric ID", "https://weibo.com/1234567", true},
		{"weibo.cn", "https://weibo.cn/username", true},
		{"homepage", "https://weibo.com", false},
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
		{"user ID", "https://weibo.com/u/1234567", "1234567"},
		{"username", "https://weibo.com/username", "username"},
		{"weibo.cn", "https://weibo.cn/user123", "user123"},
		{"with path", "https://weibo.com/username/home", "username"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
