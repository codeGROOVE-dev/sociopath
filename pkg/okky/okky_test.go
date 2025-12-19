package okky

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"valid activity page", "https://okky.kr/users/14964/activity", true},
		{"valid articles page", "https://okky.kr/users/34665/articles", true},
		{"valid https", "https://okky.kr/users/12345/activity", true},
		{"invalid domain", "https://example.com", false},
		{"invalid path", "https://okky.kr/articles/123", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractUserID(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"activity page", "https://okky.kr/users/14964/activity", "14964"},
		{"articles page", "https://okky.kr/users/34665/articles", "34665"},
		{"basic user page", "https://okky.kr/users/123", "123"},
		{"invalid url", "https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUserID(tt.url); got != tt.want {
				t.Errorf("extractUserID(%q) = %q, want %q", tt.url, got, tt.want)
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
	mockHTML := `<!DOCTYPE html><html><head><title>OKKY - 유저 활동</title></head><body><div id="__next"><script id="__NEXT_DATA__" type="application/json">{"props":{"pageProps":{"avatar":{"nickname":"testuser","oneLineSelfIntroduction":"테스트 개발자입니다","picture":"f79b670641fcc63162c610b234e51e92","pictureType":"GRAVATAR"},"socialLinkFirst":"https://github.com/testuser","socialLinkSecond":"https://twitter.com/testuser","socialLinkThird":"","activities":[{"title":"첫 번째 글","content":"테스트 내용입니다","url":"/articles/123","createdAt":"2024-12-19","type":"article"}],"counts":{"posts":42,"saved":10,"awards":5}}}}</script></div></body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(mockHTML))
	}))
	defer server.Close()

	ctx := context.Background()
	client, _ := New(ctx)

	originalURL := "https://okky.kr/users/14964/activity"
	client.httpClient.Transport = &mockTransport{
		serverURL: server.URL,
		targetURL: originalURL,
	}

	prof, err := client.Fetch(ctx, originalURL)
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if prof.Platform != "okky" {
		t.Errorf("Platform = %q, want %q", prof.Platform, "okky")
	}

	if prof.Username != "testuser" {
		t.Errorf("Username = %q, want %q", prof.Username, "testuser")
	}

	if prof.DisplayName != "testuser" {
		t.Errorf("DisplayName = %q, want %q", prof.DisplayName, "testuser")
	}

	if prof.Bio != "테스트 개발자입니다" {
		t.Errorf("Bio = %q, want %q", prof.Bio, "테스트 개발자입니다")
	}

	if prof.AvatarURL == "" {
		t.Error("AvatarURL should not be empty")
	}

	if !strings.Contains(prof.AvatarURL, "gravatar.com") {
		t.Errorf("AvatarURL = %q, should contain gravatar.com", prof.AvatarURL)
	}

	if len(prof.SocialLinks) != 2 {
		t.Errorf("SocialLinks count = %d, want 2", len(prof.SocialLinks))
	}

	if prof.Fields["posts"] != "42" {
		t.Errorf("Fields[posts] = %q, want %q", prof.Fields["posts"], "42")
	}

	if len(prof.Posts) != 1 {
		t.Errorf("Posts count = %d, want 1", len(prof.Posts))
	}
}

func TestFetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, _ := New(ctx)

	originalURL := "https://okky.kr/users/99999/activity"
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
