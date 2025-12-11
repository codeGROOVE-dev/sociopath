package vkontakte

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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

func TestExtractLocation(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "simple city class",
			html: `<span class="city">Moscow</span>`,
			want: "Moscow",
		},
		{
			name: "vkitTextClamp location",
			html: `<span class="vkitTextClamp__root--nWHhg vkitTextClamp__rootSingleLine--7YAg4">Barnaul</span>`,
			want: "", // Too generic pattern, we don't use vkitTextClamp
		},
		{
			name: "CSS content rejected",
			html: `<style>.city{color:var(--vkui--color_text_primary);}</style>`,
			want: "",
		},
		{
			name: "CSS in location rejected",
			html: `<span class="city">svg{max-height:var(--left-menu-icon-size);}</span>`,
			want: "",
		},
		{
			name: "long location truncated",
			html: `<span class="city">This is a very long location name that exceeds the maximum allowed length for a location field</span>`,
			want: "",
		},
		{
			name: "empty location",
			html: `<span class="city"></span>`,
			want: "",
		},
		{
			name: "Russian city class",
			html: `<span class="город">Санкт-Петербург</span>`,
			want: "Санкт-Петербург",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLocation(tt.html)
			if got != tt.want {
				t.Errorf("extractLocation() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsValidLocation(t *testing.T) {
	tests := []struct {
		loc  string
		want bool
	}{
		{"Moscow", true},
		{"New York, USA", true},
		{"Санкт-Петербург", true},
		{"", false},
		{"svg{max-height:var(--left-menu-icon-size);}", false},
		{"color: rgb(0,0,0)", false},
		{"margin: 10px", false},
		{".class{display:none}", false},
		{strings.Repeat("a", 65), false}, // Too long
		{strings.Repeat("a", 64), true},  // Exactly at limit
	}

	for _, tt := range tests {
		t.Run(tt.loc, func(t *testing.T) {
			got := isValidLocation(tt.loc)
			if got != tt.want {
				t.Errorf("isValidLocation(%q) = %v, want %v", tt.loc, got, tt.want)
			}
		})
	}
}

func TestTruncateLocation(t *testing.T) {
	tests := []struct {
		loc  string
		want string
	}{
		{"Moscow", "Moscow"},
		{strings.Repeat("a", 64), strings.Repeat("a", 64)},
		{strings.Repeat("a", 100), strings.Repeat("a", 64)},
	}

	for _, tt := range tests {
		t.Run(tt.loc[:min(10, len(tt.loc))], func(t *testing.T) {
			got := truncateLocation(tt.loc)
			if got != tt.want {
				t.Errorf("truncateLocation() = %q (len %d), want %q (len %d)",
					got, len(got), tt.want, len(tt.want))
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
