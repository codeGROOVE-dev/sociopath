package zerosec

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
		{"valid archive /u/ format", "https://archive.0x00sec.org/u/dtm", true},
		{"valid main site /users/", "https://0x00sec.org/users/testuser", true},
		{"valid http", "http://archive.0x00sec.org/u/test", true},
		{"invalid domain", "https://example.com/u/test", false},
		{"invalid path", "https://0x00sec.org/topics/123", false},
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
		{"archive user", "https://archive.0x00sec.org/u/dtm", "dtm"},
		{"main site user", "https://0x00sec.org/users/testuser", "testuser"},
		{"user with hyphen", "https://0x00sec.org/u/test-user", "test-user"},
		{"user with underscore", "https://0x00sec.org/u/test_user", "test_user"},
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
<head><title>testuser - 0x00sec - The Home of the Hacker</title></head>
<body>
<div class="user-profile">
	<img class="avatar" src="//archive.0x00sec.org/user_avatar/testuser/48/123_2.png" alt="avatar">
	<h1 class="username">testuser</h1>
	<div class="bio">Security researcher and reverse engineer</div>
	<div class="stats">
		<dt>Posts</dt>
		<dd>42</dd>
		<dt>Topics</dt>
		<dd>15</dd>
		<dt>Likes</dt>
		<dd>128</dd>
	</div>
	<div class="social-links">
		<a href="https://github.com/testuser">GitHub</a>
		<a href="https://twitter.com/testuser">Twitter</a>
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

	originalURL := "https://archive.0x00sec.org/u/testuser"
	client.httpClient.Transport = &mockTransport{
		serverURL: server.URL,
		targetURL: originalURL,
	}

	prof, err := client.Fetch(ctx, originalURL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if prof.Platform != "0x00sec" {
		t.Errorf("Platform = %q, want %q", prof.Platform, "0x00sec")
	}

	if prof.Username != "testuser" {
		t.Errorf("Username = %q, want %q", prof.Username, "testuser")
	}

	if prof.DisplayName != "testuser" {
		t.Errorf("DisplayName = %q, want %q", prof.DisplayName, "testuser")
	}

	if prof.Bio != "Security researcher and reverse engineer" {
		t.Errorf("Bio = %q, want %q", prof.Bio, "Security researcher and reverse engineer")
	}

	if prof.AvatarURL == "" {
		t.Error("AvatarURL should not be empty")
	}

	if len(prof.SocialLinks) != 2 {
		t.Errorf("SocialLinks count = %d, want 2", len(prof.SocialLinks))
	}
}

func TestFetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, _ := New(ctx)

	originalURL := "https://archive.0x00sec.org/u/nonexistent"
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
