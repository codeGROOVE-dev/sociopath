package youtube

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"handle format", "https://youtube.com/@username", true},
		{"channel ID", "https://youtube.com/channel/UCxxxxxx", true},
		{"c/ format", "https://youtube.com/c/ChannelName", true},
		{"user format", "https://youtube.com/user/username", true},
		{"www variant", "https://www.youtube.com/@handle", true},
		{"video URL", "https://youtube.com/watch?v=xxxxx", false},
		{"other domain", "https://vimeo.com/user", false},
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
		{"handle", "https://youtube.com/@johndoe", "johndoe"},
		{"channel ID", "https://youtube.com/channel/UC123456", "UC123456"},
		{"c/ format", "https://youtube.com/c/MyChannel", "MyChannel"},
		{"user format", "https://youtube.com/user/olduser", "olduser"},
		{"invalid", "https://youtube.com/watch", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
