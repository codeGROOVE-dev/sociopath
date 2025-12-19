package nexusmods

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"valid www users", "https://www.nexusmods.com/users/DarkOne", true},
		{"valid www user singular", "https://www.nexusmods.com/user/testuser", true},
		{"valid next profile", "https://next.nexusmods.com/profile/modder123", true},
		{"valid http", "http://www.nexusmods.com/users/test", true},
		{"invalid domain", "https://example.com/users/test", false},
		{"invalid path", "https://www.nexusmods.com/games/skyrim", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"www users", "https://www.nexusmods.com/users/DarkOne", "DarkOne"},
		{"next profile", "https://next.nexusmods.com/profile/modder123", "modder123"},
		{"user with hyphen", "https://www.nexusmods.com/users/test-user", "test-user"},
		{"user with underscore", "https://www.nexusmods.com/users/test_user", "test_user"},
		{"invalid url", "https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}
}

func TestFetch(t *testing.T) {
	mockHTML := `<!DOCTYPE html>
<html>
<head>
	<title>testmodder's Profile - Nexus Mods</title>
	<meta name="description" content="Skyrim modder creating immersive gameplay experiences">
</head>
<body>
<div class="user-profile">
	<img class="avatar" src="https://staticdelivery.nexusmods.com/avatars/123/avatar.png" alt="avatar">
	<h1 class="username">testmodder</h1>
	<div class="bio">Creating immersive mods for Elder Scrolls games</div>
	<div class="stats">
		<div class="stat">Mods: 15</div>
		<div class="stat">Downloads: 2.5M</div>
		<div class="stat">Endorsements: 45000</div>
	</div>
	<div class="social-links">
		<a href="https://github.com/testmodder">GitHub</a>
		<a href="https://twitter.com/testmodder">Twitter</a>
		<a href="https://www.patreon.com/testmodder">Patreon</a>
	</div>
</div>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockHTML))
	}))
	defer server.Close()

	ctx := context.Background()
	client, _ := New(ctx)

	originalURL := "https://www.nexusmods.com/users/testmodder"
	client.httpClient.Transport = &mockTransport{
		serverURL: server.URL,
		targetURL: originalURL,
	}

	prof, err := client.Fetch(ctx, originalURL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if prof.Platform != "nexusmods" {
		t.Errorf("Platform = %q, want %q", prof.Platform, "nexusmods")
	}

	if prof.Username != "testmodder" {
		t.Errorf("Username = %q, want %q", prof.Username, "testmodder")
	}

	if prof.DisplayName != "testmodder" {
		t.Errorf("DisplayName = %q, want %q", prof.DisplayName, "testmodder")
	}

	if prof.Bio != "Skyrim modder creating immersive gameplay experiences" {
		t.Errorf("Bio = %q, want %q", prof.Bio, "Skyrim modder creating immersive gameplay experiences")
	}

	if prof.AvatarURL == "" {
		t.Error("AvatarURL should not be empty")
	}

	// htmlutil.SocialLinks may not extract all links depending on its internal patterns
	if len(prof.SocialLinks) < 2 {
		t.Errorf("SocialLinks count = %d, want at least 2", len(prof.SocialLinks))
	}
}

func TestFetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, _ := New(ctx)

	originalURL := "https://www.nexusmods.com/users/nonexistent"
	client.httpClient.Transport = &mockTransport{
		serverURL: server.URL,
		targetURL: originalURL,
	}

	_, err := client.Fetch(ctx, originalURL)
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

// mockTransport redirects requests to our test server
type mockTransport struct {
	serverURL string
	targetURL string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Parse the test server URL
	serverURL, err := url.Parse(t.serverURL)
	if err != nil {
		return nil, err
	}

	// Redirect the request to the test server
	req.URL.Scheme = serverURL.Scheme
	req.URL.Host = serverURL.Host

	return http.DefaultTransport.RoundTrip(req)
}
