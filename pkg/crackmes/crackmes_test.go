package crackmes

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
		{"valid user profile", "https://crackmes.one/user/nukoneZ", true},
		{"valid http", "http://crackmes.one/user/testuser", true},
		{"valid with trailing slash", "https://crackmes.one/user/test123/", true},
		{"invalid domain", "https://example.com/user/test", false},
		{"invalid path", "https://crackmes.one/crackmes/123", false},
		{"missing username", "https://crackmes.one/user/", false},
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
		{"standard user", "https://crackmes.one/user/nukoneZ", "nukoneZ"},
		{"user with hyphen", "https://crackmes.one/user/test-user", "test-user"},
		{"user with underscore", "https://crackmes.one/user/test_user", "test_user"},
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
<head><title>testuser's profile - Crackmes.one</title></head>
<body>
<div class="profile">
	<h1>testuser's profile</h1>
	<div class="stats">
		<p>Crackmes submitted: 5</p>
		<p>Writeups authored: 3</p>
		<p>Comments made: 12</p>
	</div>
	<div class="social">
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

	originalURL := "https://crackmes.one/user/testuser"
	client.httpClient.Transport = &mockTransport{
		serverURL: server.URL,
		targetURL: originalURL,
	}

	prof, err := client.Fetch(ctx, originalURL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if prof.Platform != "crackmes" {
		t.Errorf("Platform = %q, want %q", prof.Platform, "crackmes")
	}

	if prof.Username != "testuser" {
		t.Errorf("Username = %q, want %q", prof.Username, "testuser")
	}

	if prof.DisplayName != "testuser" {
		t.Errorf("DisplayName = %q, want %q", prof.DisplayName, "testuser")
	}

	if prof.Fields["crackmes_submitted"] != "5" {
		t.Errorf("Fields[crackmes_submitted] = %q, want %q", prof.Fields["crackmes_submitted"], "5")
	}

	if prof.Fields["writeups"] != "3" {
		t.Errorf("Fields[writeups] = %q, want %q", prof.Fields["writeups"], "3")
	}

	if prof.Fields["comments"] != "12" {
		t.Errorf("Fields[comments] = %q, want %q", prof.Fields["comments"], "12")
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

	originalURL := "https://crackmes.one/user/nonexistent"
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
