package github

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://github.com/torvalds", true},
		{"https://github.com/octocat", true},
		{"github.com/username", true},
		{"https://github.com/user123", true},
		{"https://github.com/features", false},
		{"https://github.com/marketplace", false},
		{"https://github.com/torvalds/linux", false}, // repo, not profile
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
		{"https://github.com/torvalds", "torvalds"},
		{"https://github.com/octocat", "octocat"},
		{"github.com/user_name", "user_name"},
		{"https://github.com/user?tab=repositories", "user"},
		{"https://www.github.com/someone", "someone"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseJSON(t *testing.T) {
	sampleJSON := `{
		"login": "octocat",
		"name": "The Octocat",
		"bio": "GitHub's mascot",
		"location": "San Francisco",
		"blog": "https://github.blog",
		"email": "octocat@github.com",
		"twitter_username": "github",
		"company": "@github",
		"public_repos": 8,
		"followers": 5000,
		"following": 9,
		"avatar_url": "https://avatars.githubusercontent.com/u/583231",
		"html_url": "https://github.com/octocat",
		"type": "User"
	}`

	p, err := parseJSON([]byte(sampleJSON), "https://github.com/octocat", "octocat")
	if err != nil {
		t.Fatalf("parseJSON failed: %v", err)
	}

	if p.Username != "octocat" {
		t.Errorf("Username = %q, want %q", p.Username, "octocat")
	}

	if p.Name != "The Octocat" {
		t.Errorf("Name = %q, want %q", p.Name, "The Octocat")
	}

	if p.Bio != "GitHub's mascot" {
		t.Errorf("Bio = %q, want %q", p.Bio, "GitHub's mascot")
	}

	if p.Location != "San Francisco" {
		t.Errorf("Location = %q, want %q", p.Location, "San Francisco")
	}

	if p.Website != "https://github.blog" {
		t.Errorf("Website = %q, want %q", p.Website, "https://github.blog")
	}

	if p.Fields["email"] != "octocat@github.com" {
		t.Errorf("email = %q, want %q", p.Fields["email"], "octocat@github.com")
	}

	if p.Fields["company"] != "github" {
		t.Errorf("company = %q, want %q", p.Fields["company"], "github")
	}

	if p.Fields["twitter"] != "https://twitter.com/github" {
		t.Errorf("twitter = %q, want %q", p.Fields["twitter"], "https://twitter.com/github")
	}

	if p.Fields["type"] != "User" {
		t.Errorf("type = %q, want %q", p.Fields["type"], "User")
	}

	if len(p.SocialLinks) != 1 {
		t.Errorf("SocialLinks length = %d, want 1", len(p.SocialLinks))
	}
}
