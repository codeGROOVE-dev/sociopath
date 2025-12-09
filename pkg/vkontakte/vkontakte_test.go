package vkontakte

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://vk.com/johndoe", true},
		{"https://vk.com/id12345", true},
		{"https://VK.COM/johndoe", true},
		{"https://twitter.com/johndoe", false},
		{"https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := Match(tt.url)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("VKontakte should not strictly require auth (cookies optional for bot detection)")
	}
}

func TestNewWithoutCookies(t *testing.T) {
	client, err := New(context.Background())
	if err != nil {
		t.Errorf("New() without cookies should succeed (cookies optional): %v", err)
	}
	if client == nil {
		t.Error("client should not be nil")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://vk.com/xrock", "xrock"},
		{"https://vk.com/id12345", "id12345"},
		{"vk.com/johndoe", "johndoe"},
		{"https://www.vk.com/username", "username"},
		{"https://vk.com/user?query=1", "user"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractUsername(tt.url)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	mockHTML := `<!DOCTYPE html>
<html>
<head>
<title>Ivan Petrov | VK</title>
<meta name="description" content="Software developer from Moscow">
</head>
<body>
<span class="birthday">January 15</span>
<span class="city">Moscow</span>
<a href="https://github.com/ivanpetrov">GitHub</a>
<a href="https://twitter.com/ivanpetrov">Twitter</a>
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

	profile, err := client.Fetch(ctx, "https://vk.com/ivanpetrov")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "vkontakte" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "vkontakte")
	}
	if profile.Username != "ivanpetrov" {
		t.Errorf("Username = %q, want %q", profile.Username, "ivanpetrov")
	}
	if profile.Name != "Ivan Petrov" {
		t.Errorf("Name = %q, want %q", profile.Name, "Ivan Petrov")
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

	_, err = client.Fetch(ctx, "https://vk.com/nonexistent")
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		url      string
		wantName string
		wantBio  string
		wantErr  bool
	}{
		{
			name: "full profile",
			html: `<html><head>
				<title>John Doe | VK</title>
				<meta name="description" content="Developer and designer">
			</head><body></body></html>`,
			url:      "https://vk.com/johndoe",
			wantName: "John Doe",
			wantBio:  "Developer and designer",
		},
		{
			name:    "bot detection triggered",
			html:    `<html><body>You are making too many requests</body></html>`,
			url:     "https://vk.com/user",
			wantErr: true,
		},
		{
			name:    "Russian bot detection",
			html:    `<html><body>У вас большие запросы</body></html>`,
			url:     "https://vk.com/user",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := parseProfile(tt.html, tt.url)

			if tt.wantErr {
				if err == nil {
					t.Error("parseProfile() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseProfile() error = %v", err)
			}

			if profile.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.Name, tt.wantName)
			}
			if tt.wantBio != "" && profile.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", profile.Bio, tt.wantBio)
			}
		})
	}
}

func TestWithOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("with_cookies", func(t *testing.T) {
		client, err := New(ctx, WithCookies(map[string]string{"test": "value"}))
		if err != nil {
			t.Fatalf("New(WithCookies) error = %v", err)
		}
		if client == nil {
			t.Fatal("New(WithCookies) returned nil")
		}
	})

	t.Run("with_browser_cookies_option", func(t *testing.T) {
		// Verify WithBrowserCookies option compiles and can be passed
		// We don't actually call New() with it to avoid slow browser access
		opt := WithBrowserCookies()
		if opt == nil {
			t.Fatal("WithBrowserCookies() returned nil")
		}
	})
}
