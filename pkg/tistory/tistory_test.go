package tistory

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
		{"valid tistory blog", "https://jojoldu.tistory.com", true},
		{"valid with path", "https://jojoldu.tistory.com/123", true},
		{"valid http", "http://myblog.tistory.com", true},
		{"invalid domain", "https://example.com", false},
		{"substack not tistory", "https://myblog.substack.com", false},
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
		{"basic blog", "https://jojoldu.tistory.com", "jojoldu"},
		{"with path", "https://myblog.tistory.com/123", "myblog"},
		{"http protocol", "http://test-blog.tistory.com", "test-blog"},
		{"with underscores", "https://my_blog.tistory.com", "my_blog"},
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
	<title>기억보단 기록을</title>
	<meta name="description" content="IT 개발자의 기술 블로그">
	<meta property="og:image" content="https://tistory1.daumcdn.net/tistory/1826700/attach/test.jpg">
</head>
<body>
	<div class="header">
		<img src="https://tistory1.daumcdn.net/tistory/1826700/attach/blog-image.jpg" alt="블로그 이미지">
	</div>
	<div class="article-list">
		<div class="article">
			<h3 class="title"><a href="/123">테스트 포스트 제목</a></h3>
			<p class="excerpt">이것은 테스트 포스트의 요약입니다.</p>
			<span class="date">2024.12.19</span>
		</div>
	</div>
	<div class="social">
		<a href="https://github.com/jojoldu">GitHub</a>
		<a href="https://twitter.com/jojoldu">Twitter</a>
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

	// Replace the client's HTTP client to use our test server
	originalURL := "https://testblog.tistory.com"
	client.httpClient.Transport = &mockTransport{
		serverURL: server.URL,
		targetURL: originalURL,
	}

	prof, err := client.Fetch(ctx, originalURL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if prof.Username != "testblog" {
		t.Errorf("Username = %q, want %q", prof.Username, "testblog")
	}

	if prof.Platform != "tistory" {
		t.Errorf("Platform = %q, want %q", prof.Platform, "tistory")
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

	originalURL := "https://nonexistent.tistory.com"
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
