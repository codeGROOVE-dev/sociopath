package htmlutil

import (
	"slices"
	"testing"
)

func TestExtractEmailFromURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantEmail string
		wantOK    bool
	}{
		{
			name:      "http basic auth URL is not an email",
			url:       "https://user@example.com",
			wantEmail: "",
			wantOK:    false,
		},
		{
			name:      "http with gmail email",
			url:       "http://sanchita.mishra1718@gmail.com",
			wantEmail: "sanchita.mishra1718@gmail.com",
			wantOK:    true,
		},
		{
			name:      "https with outlook email",
			url:       "https://user@outlook.com",
			wantEmail: "user@outlook.com",
			wantOK:    true,
		},
		{
			name:      "regular https URL",
			url:       "https://example.com",
			wantEmail: "",
			wantOK:    false,
		},
		{
			name:      "email without protocol",
			url:       "user@example.com",
			wantEmail: "",
			wantOK:    false,
		},
		{
			name:      "http basic auth with path is not email",
			url:       "https://user@example.com/path",
			wantEmail: "",
			wantOK:    false,
		},
		{
			name:      "HTTPS uppercase with known provider",
			url:       "HTTPS://user@gmail.com",
			wantEmail: "user@gmail.com",
			wantOK:    true,
		},
		{
			name:      "unknown domain is not treated as email",
			url:       "https://user@domain.com",
			wantEmail: "",
			wantOK:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEmail, gotOK := ExtractEmailFromURL(tt.url)
			if gotEmail != tt.wantEmail {
				t.Errorf("ExtractEmailFromURL(%q) email = %q, want %q", tt.url, gotEmail, tt.wantEmail)
			}
			if gotOK != tt.wantOK {
				t.Errorf("ExtractEmailFromURL(%q) ok = %v, want %v", tt.url, gotOK, tt.wantOK)
			}
		})
	}
}

func TestIsEmailURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"http basic auth is not email", "https://user@example.com", false},
		{"http with known provider is email", "http://user@gmail.com", true},
		{"mailto link", "mailto:user@example.com", true},
		{"mailto uppercase", "MAILTO:user@example.com", true},
		{"regular URL", "https://example.com", false},
		{"email without protocol", "user@example.com", false},
		{"github URL", "https://github.com/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEmailURL(tt.url); got != tt.want {
				t.Errorf("IsEmailURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestRelMeLinks(t *testing.T) {
	tests := []struct {
		name string
		html string
		want []string
	}{
		{
			name: "rel me link with href first",
			html: `<a href="https://twitter.com/lizthegrey" rel="me">Twitter</a>`,
			want: []string{"https://twitter.com/lizthegrey"},
		},
		{
			name: "rel me link with rel first",
			html: `<a rel="me" href="https://github.com/lizthegrey">GitHub</a>`,
			want: []string{"https://github.com/lizthegrey"},
		},
		{
			name: "rel me with other values",
			html: `<a href="https://mastodon.social/@liz" rel="noopener me noreferrer">Mastodon</a>`,
			want: []string{"https://mastodon.social/@liz"},
		},
		{
			name: "regular link without rel me is ignored",
			html: `<a href="https://twitter.com/sethvargo">Seth Vargo</a>`,
			want: nil,
		},
		{
			name: "mixed rel me and regular links",
			html: `<p>Follow me: <a href="https://twitter.com/lizthegrey" rel="me">@lizthegrey</a></p>
			       <p>Co-author: <a href="https://twitter.com/sethvargo">@sethvargo</a></p>`,
			want: []string{"https://twitter.com/lizthegrey"},
		},
		{
			name: "multiple rel me links",
			html: `<a rel="me" href="https://twitter.com/user">Twitter</a>
			       <a rel="me" href="https://github.com/user">GitHub</a>`,
			want: []string{"https://twitter.com/user", "https://github.com/user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RelMeLinks(tt.html)
			if len(got) != len(tt.want) {
				t.Errorf("RelMeLinks() = %v, want %v", got, tt.want)
				return
			}
			for i, u := range got {
				if u != tt.want[i] {
					t.Errorf("RelMeLinks()[%d] = %q, want %q", i, u, tt.want[i])
				}
			}
		})
	}
}

func TestEmailAddresses(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		want    []string
		notWant []string
	}{
		{
			name:    "valid email",
			html:    `<p>Contact me at test@gmail.com</p>`,
			want:    []string{"test@gmail.com"},
			notWant: nil,
		},
		{
			name:    "bogus TLD filtered",
			html:    `<p>u+tko@hrdacmqtem.sqdro</p>`,
			want:    nil,
			notWant: []string{"u+tko@hrdacmqtem.sqdro"},
		},
		{
			name:    "noreply filtered",
			html:    `<p>noreply@example.com</p>`,
			want:    nil,
			notWant: []string{"noreply@example.com"},
		},
		{
			name:    "multiple with bogus filtered",
			html:    `<p>valid@gmail.com and bogus@xyzqw.tklrm</p>`,
			want:    []string{"valid@gmail.com"},
			notWant: []string{"bogus@xyzqw.tklrm"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EmailAddresses(tt.html)
			for _, want := range tt.want {
				if !slices.Contains(got, want) {
					t.Errorf("EmailAddresses() missing %q, got %v", want, got)
				}
			}
			for _, notWant := range tt.notWant {
				if slices.Contains(got, notWant) {
					t.Errorf("EmailAddresses() should not contain %q, got %v", notWant, got)
				}
			}
		})
	}
}

func TestExtractDiscordUsername(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "old format with discriminator",
			content: "How to reach me discord StarGhost#8077",
			want:    "StarGhost#8077",
		},
		{
			name:    "old format in sentence",
			content: "Contact me on Discord: JohnDoe#1234 for questions",
			want:    "JohnDoe#1234",
		},
		{
			name:    "old format with dots",
			content: "My Discord is user.name#5678",
			want:    "user.name#5678",
		},
		{
			name:    "new format with context",
			content: "Discord: newusername",
			want:    "newusername",
		},
		{
			name:    "new format with colon and space",
			content: "discord: cooldev",
			want:    "cooldev",
		},
		{
			name:    "new format with leading dot",
			content: "Discord: .dotuser",
			want:    ".dotuser",
		},
		{
			name:    "no discord username",
			content: "Hello, I'm a developer from San Francisco.",
			want:    "",
		},
		{
			name:    "github readme style",
			content: "- 📫 How to reach me discord StarGhost#8077",
			want:    "StarGhost#8077",
		},
		{
			name:    "invalid discriminator (3 digits)",
			content: "User#123 is not valid",
			want:    "",
		},
		{
			name:    "invalid discriminator (5 digits)",
			content: "User#12345 is not valid on discord",
			want:    "",
		},
		{
			name:    "no discord mention - ignore pattern",
			content: "Contact me: JohnDoe#1234",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractDiscordUsername(tt.content)
			if got != tt.want {
				t.Errorf("ExtractDiscordUsername(%q) = %q, want %q", tt.content, got, tt.want)
			}
		})
	}
}
