package discovery

import "testing"

func TestIsKnownSocialDomain(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		// Known social domains
		{"github.com", true},
		{"twitter.com", true},
		{"x.com", true},
		{"linkedin.com", true},
		{"instagram.com", true},
		{"mastodon.social", true},
		{"bsky.app", true},
		{"keybase.io", true},
		{"reddit.com", true},
		{"youtube.com", true},
		{"medium.com", true},
		{"dev.to", true},

		// Subdomains of known platforms
		{"gist.github.com", true},
		{"api.twitter.com", true},
		{"m.facebook.com", true},

		// Hosting platforms
		{"user.github.io", true},
		{"project.gitlab.io", true},
		{"mysite.netlify.app", true},
		{"app.vercel.app", true},
		{"site.pages.dev", true},

		// Personal domains (should NOT be known)
		{"dave.coffee", false},
		{"stromberg.org", false},
		{"simonwillison.net", false},
		{"alex.zenla.io", false},
		{"example.com", false},
		{"myblog.io", false},

		// Case insensitivity
		{"GITHUB.COM", true},
		{"GitHub.com", true},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := IsKnownSocialDomain(tt.domain)
			if got != tt.want {
				t.Errorf("IsKnownSocialDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestExtractDomain(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/user", "github.com"},
		{"http://example.com/path", "example.com"},
		{"https://www.example.com/path", "example.com"},
		{"https://WWW.Example.COM/path", "example.com"},
		{"example.com/path", "example.com"},
		{"dave.coffee", "dave.coffee"},
		{"https://subdomain.example.com", "subdomain.example.com"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := ExtractDomain(tt.url)
			if got != tt.want {
				t.Errorf("ExtractDomain(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
