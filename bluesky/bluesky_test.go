package bluesky

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://bsky.app/profile/johndoe.bsky.social", true},
		{"https://bsky.app/profile/johndoe.com", true},
		{"https://staging.bsky.app/profile/johndoe", true},
		{"https://twitter.com/johndoe", false},
		{"https://mastodon.social/@johndoe", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := Match(tt.url)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("BlueSky should not require auth")
	}
}

func TestExtractHandle(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://bsky.app/profile/johndoe.bsky.social", "johndoe.bsky.social"},
		{"https://bsky.app/profile/custom.domain", "custom.domain"},
		{"https://bsky.app/profile/johndoe/posts", "johndoe"},
		{"https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractHandle(tt.url)
			if got != tt.want {
				t.Errorf("extractHandle(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
