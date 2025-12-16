//nolint:gosmopolitan // Chinese platform requires Chinese characters in tests
package bilibili

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"space URL", "https://space.bilibili.com/123456", true},
		{"short URL", "https://bilibili.com/123456", true},
		{"with path", "https://space.bilibili.com/123456/dynamic", true},
		{"video URL", "https://bilibili.com/video/BV123", false},
		{"other domain", "https://youtube.com/watch", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("AuthRequired() = true, want false")
	}
}

func TestExtractUserID(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"space URL", "https://space.bilibili.com/123456", "123456"},
		{"short URL", "https://bilibili.com/987654", "987654"},
		{"with path", "https://space.bilibili.com/123456/video", "123456"},
		{"no protocol", "space.bilibili.com/111222", "111222"},
		{"invalid", "https://bilibili.com/video/BV123", ""},
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
	mockHTML := `<!DOCTYPE html>
<html>
<head>
<title>测试用户的个人空间_哔哩哔哩_bilibili</title>
<meta name="description" content="欢迎关注我的频道">
</head>
<body>
<span>1000 粉丝</span>
<span>50 关注</span>
<span>25 投稿</span>
<a href="https://twitter.com/testuser">Twitter</a>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockHTML)) //nolint:errcheck // test helper
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	profile, err := client.Fetch(ctx, "https://space.bilibili.com/123456")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "bilibili" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "bilibili")
	}
	if profile.Username != "123456" {
		t.Errorf("Username = %q, want %q", profile.Username, "123456")
	}
	if profile.DisplayName != "测试用户" {
		t.Errorf("Name = %q, want %q", profile.DisplayName, "测试用户")
	}
}

type mockTransport struct {
	mockURL string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = t.mockURL[7:] // Strip "http://"
	return http.DefaultTransport.RoundTrip(req)
}

func TestFetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	_, err = client.Fetch(ctx, "https://space.bilibili.com/999999")
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

func TestFetch_InvalidUserID(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, "https://bilibili.com/video/BV123")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name          string
		html          string
		userID        string
		wantName      string
		wantFollowers string
	}{
		{
			name: "full profile",
			html: `<html><head>
				<title>大神UP的个人空间_哔哩哔哩_bilibili</title>
				<meta name="description" content="游戏区UP主">
			</head><body>
				<span>10万 粉丝</span>
				<span>100 关注</span>
			</body></html>`,
			userID:        "12345",
			wantName:      "大神UP",
			wantFollowers: "10万",
		},
		{
			name: "English fans label",
			html: `<html><head>
				<title>TestUser的个人空间</title>
			</head><body>
				<span>5000 fans</span>
			</body></html>`,
			userID:        "67890",
			wantName:      "TestUser",
			wantFollowers: "5000",
		},
		{
			name: "empty page uses userID",
			html: `<html><head>
				<title></title>
			</head><body></body></html>`,
			userID:   "fallback123",
			wantName: "fallback123",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := parseProfile(tt.html, "https://space.bilibili.com/"+tt.userID, tt.userID)
			if err != nil {
				t.Fatalf("parseProfile() error = %v", err)
			}

			if profile.DisplayName != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.DisplayName, tt.wantName)
			}
			if tt.wantFollowers != "" && profile.Fields["followers"] != tt.wantFollowers {
				t.Errorf("followers = %q, want %q", profile.Fields["followers"], tt.wantFollowers)
			}
		})
	}
}

func TestWithOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("with_logger", func(t *testing.T) {
		client, err := New(ctx, WithLogger(nil))
		if err != nil {
			t.Fatalf("New(WithLogger) error = %v", err)
		}
		if client == nil {
			t.Fatal("New(WithLogger) returned nil")
		}
	})

	t.Run("with_cache", func(t *testing.T) {
		client, err := New(ctx, WithHTTPCache(nil))
		if err != nil {
			t.Fatalf("New(WithHTTPCache) error = %v", err)
		}
		if client == nil {
			t.Fatal("New(WithHTTPCache) returned nil")
		}
	})
}
