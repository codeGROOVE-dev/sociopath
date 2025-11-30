package bilibili

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"space URL", "https://space.bilibili.com/123456", true},
		{"short URL", "https://bilibili.com/123456", true},
		{"with path", "https://space.bilibili.com/123456/dynamic", true},
		{"video URL", "https://bilibili.com/video/BV123", false},
		{"other domain", "https://youtube.com/watch", false},
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

func TestExtractUserID(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"space URL", "https://space.bilibili.com/123456", "123456"},
		{"short URL", "https://bilibili.com/987654", "987654"},
		{"with path", "https://space.bilibili.com/123456/video", "123456"},
		{"invalid", "https://bilibili.com/video/BV123", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUserID(tt.url); got != tt.want {
				t.Errorf("extractUserID(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
