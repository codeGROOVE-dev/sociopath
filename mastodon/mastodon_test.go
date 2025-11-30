package mastodon

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://mastodon.social/@johndoe", true},
		{"https://fosstodon.org/@johndoe", true},
		{"https://hachyderm.io/@johndoe", true},
		{"https://infosec.exchange/@johndoe", true},
		{"https://example.social/@johndoe", true},
		{"https://mastodon.social/users/johndoe", true},
		{"https://twitter.com/johndoe", false},
		{"https://linkedin.com/in/johndoe", false},
		{"https://example.com/about", false},
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
		t.Error("Mastodon should not require auth")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/@johndoe", "johndoe"},
		{"/users/johndoe", "johndoe"},
		{"/@johndoe/followers", "johndoe"},
		{"/about", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractUsername(tt.path)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestStripHTML(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"<p>Hello</p>", "Hello"},
		{"<p>Hello</p><p>World</p>", "Hello\nWorld"},
		{"Hello &amp; World", "Hello & World"},
		{"<a href='url'>link</a>", "link"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := stripHTML(tt.input)
			if got != tt.want {
				t.Errorf("stripHTML(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
