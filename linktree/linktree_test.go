package linktree

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://linktr.ee/johndoe", true},
		{"https://www.linktr.ee/johndoe", true},
		{"http://linktr.ee/johndoe", true},
		{"linktr.ee/johndoe", true},
		{"https://linktree.com/johndoe", true},
		{"https://twitter.com/johndoe", false},
		{"https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://linktr.ee/johndoe", "johndoe"},
		{"https://linktr.ee/Udi_Hofesh", "Udi_Hofesh"},
		{"linktr.ee/test123", "test123"},
		{"https://linktr.ee/user?ref=abc", "user"},
		{"https://linktree.com/johndoe", "johndoe"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseNextData(t *testing.T) {
	// Sample embedded JSON that mimics Linktree's __NEXT_DATA__
	sampleJSON := `{
		"props": {
			"pageProps": {
				"account": {
					"username": "testuser",
					"profileTitle": "Test User",
					"description": "Developer at Company"
				},
				"links": [
					{"url": "https://twitter.com/testuser", "title": "Twitter"},
					{"url": "https://linkedin.com/in/testuser", "title": "LinkedIn"},
					{"url": "https://example.com", "title": "My Website"}
				],
				"socialLinks": [
					{"url": "https://github.com/testuser", "type": "GITHUB"}
				]
			}
		}
	}`

	html := `<html><script id="__NEXT_DATA__" type="application/json">` + sampleJSON + `</script></html>`

	p := parseHTML([]byte(html), "https://linktr.ee/testuser", "testuser")

	if p.Name != "Test User" {
		t.Errorf("Name = %q, want %q", p.Name, "Test User")
	}

	if p.Bio != "Developer at Company" {
		t.Errorf("Bio = %q, want %q", p.Bio, "Developer at Company")
	}

	if p.Fields["twitter"] != "https://twitter.com/testuser" {
		t.Errorf("twitter = %q, want %q", p.Fields["twitter"], "https://twitter.com/testuser")
	}

	if p.Fields["linkedin"] != "https://linkedin.com/in/testuser" {
		t.Errorf("linkedin = %q, want %q", p.Fields["linkedin"], "https://linkedin.com/in/testuser")
	}

	if p.Fields["github"] != "https://github.com/testuser" {
		t.Errorf("github = %q, want %q", p.Fields["github"], "https://github.com/testuser")
	}

	if p.Website != "https://example.com" {
		t.Errorf("Website = %q, want %q", p.Website, "https://example.com")
	}
}
