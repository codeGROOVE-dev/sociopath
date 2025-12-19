package programmers

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
		{"valid profile page", "https://programmers.co.kr/profile/testuser", true},
		{"valid users page", "https://programmers.co.kr/users/testuser", true},
		{"valid with https", "https://programmers.co.kr/profile/test-123", true},
		{"invalid domain", "https://example.com", false},
		{"invalid path", "https://programmers.co.kr/learn", false},
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
		{"profile page", "https://programmers.co.kr/profile/testuser", "testuser"},
		{"users page", "https://programmers.co.kr/users/myblog", "myblog"},
		{"with hyphens", "https://programmers.co.kr/profile/test-user", "test-user"},
		{"with underscores", "https://programmers.co.kr/profile/test_user", "test_user"},
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
	mockHTML := `
<!DOCTYPE html>
<html>
<head>
	<title>testuser - 프로그래머스</title>
	<meta name="description" content="코딩 테스트 연습">
	<meta property="og:image" content="https://programmers.co.kr/assets/profile.jpg">
</head>
<body>
	<div class="profile">
		<img src="https://programmers.co.kr/assets/avatar.jpg" alt="프로필 이미지" class="profile-image">
		<h1>testuser</h1>
	</div>
	<div class="stats">
		<div class="stat-item">
			<span class="stat-value">42</span>
			<span class="stat-label">문제 풀이</span>
		</div>
		<div class="rank-item">
			<span class="rank-value">1,234위</span>
			<span class="rank-label">랭킹</span>
		</div>
		<div class="level-item">
			<span>레벨 3</span>
		</div>
	</div>
	<div class="social-links">
		<a href="https://github.com/testuser">GitHub</a>
		<a href="https://blog.testuser.com">Blog</a>
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

	originalURL := "https://programmers.co.kr/profile/testuser"
	client.httpClient.Transport = &mockTransport{
		serverURL: server.URL,
		targetURL: originalURL,
	}

	prof, err := client.Fetch(ctx, originalURL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if prof.Username != "testuser" {
		t.Errorf("Username = %q, want %q", prof.Username, "testuser")
	}

	if prof.Platform != "programmers" {
		t.Errorf("Platform = %q, want %q", prof.Platform, "programmers")
	}

	if prof.DisplayName == "" {
		t.Error("DisplayName should not be empty")
	}
}

func TestFetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, _ := New(ctx)

	originalURL := "https://programmers.co.kr/profile/nonexistent"
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
