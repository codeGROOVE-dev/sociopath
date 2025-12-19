package naverblog

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
		{"valid naver blog", "https://blog.naver.com/testuser", true},
		{"valid with post", "https://blog.naver.com/testuser/123", true},
		{"valid http", "http://blog.naver.com/myblog", true},
		{"invalid domain", "https://example.com", false},
		{"tistory not naver", "https://myblog.tistory.com", false},
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
		{"basic blog", "https://blog.naver.com/testuser", "testuser"},
		{"with post", "https://blog.naver.com/myblog/123", "myblog"},
		{"http protocol", "http://blog.naver.com/test-blog", "test-blog"},
		{"with underscores", "https://blog.naver.com/my_blog", "my_blog"},
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
	<title>테스트 블로그 : Naver 블로그</title>
	<meta name="description" content="개발자의 일상과 기술 이야기">
	<meta property="og:image" content="https://blogpfthumb-phinf.pstatic.net/test.jpg">
</head>
<body>
	<div class="profile">
		<img src="https://blogpfthumb-phinf.pstatic.net/profile.jpg" alt="프로필 이미지" class="profile-image">
	</div>
	<div class="post-list">
		<div class="post-item">
			<h3 class="post-title"><a href="/testuser/123">테스트 포스트</a></h3>
			<p class="post-excerpt">이것은 테스트 포스트의 요약입니다.</p>
			<span class="post-date">2024.12.19</span>
		</div>
	</div>
	<div class="links">
		<a href="https://github.com/testuser">GitHub</a>
		<a href="https://twitter.com/testuser">Twitter</a>
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

	originalURL := "https://blog.naver.com/testuser"
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

	if prof.Platform != "naverblog" {
		t.Errorf("Platform = %q, want %q", prof.Platform, "naverblog")
	}

	if prof.DisplayName == "" {
		t.Error("DisplayName should not be empty")
	}

	if prof.Bio == "" {
		t.Error("Bio should not be empty")
	}

	if len(prof.Posts) == 0 {
		t.Error("Posts should not be empty")
	}
}

func TestFetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, _ := New(ctx)

	originalURL := "https://blog.naver.com/nonexistent"
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
