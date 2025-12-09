package medium

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
		{"standard profile", "https://medium.com/@username", true},
		{"no protocol", "medium.com/@username", true},
		{"with path", "https://medium.com/@username/article-title", true},
		{"user path", "https://medium.com/user/username", true},
		{"non-profile", "https://medium.com/publication", false},
		{"other domain", "https://twitter.com/@username", false},
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

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"standard", "https://medium.com/@kentcdodds", "kentcdodds"},
		{"no protocol", "medium.com/@username", "username"},
		{"with article", "https://medium.com/@user/article-123", "user"},
		{"user path", "https://medium.com/user/johndoe", "johndoe"},
		{"invalid", "https://medium.com/publication", ""},
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
<title>Ev Williams - Medium</title>
<meta name="description" content="CEO of Medium. Former co-founder of Twitter.">
</head>
<body>
<span>10K Followers</span>
<a href="https://twitter.com/ev">Twitter</a>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockHTML)) //nolint:errcheck // test helper
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Override httpClient to redirect to mock server
	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	profile, err := client.Fetch(ctx, "https://medium.com/@ev")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "medium" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "medium")
	}
	if profile.Username != "ev" {
		t.Errorf("Username = %q, want %q", profile.Username, "ev")
	}
	if profile.Name != "Ev Williams" {
		t.Errorf("Name = %q, want %q", profile.Name, "Ev Williams")
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
	mockHTML := `<!DOCTYPE html><html><head><title>Page not found - Medium</title></head><body>Page not found</body></html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)     // Medium returns 200 with error page
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

	_, err = client.Fetch(ctx, "https://medium.com/@nonexistent")
	if err == nil {
		t.Error("Fetch() expected error for not found page, got nil")
	}
}

func TestFetch_InvalidUsername(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, "https://medium.com/publication")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		username string
		wantName string
		wantBio  string
		wantErr  bool
	}{
		{
			name: "full profile",
			html: `<html><head>
				<title>Jane Doe - Medium</title>
				<meta name="description" content="Writer and developer.">
			</head><body>
				<span>5K Followers</span>
			</body></html>`,
			username: "janedoe",
			wantName: "Jane Doe",
			wantBio:  "Writer and developer.",
		},
		{
			name: "en dash separator",
			html: `<html><head>
				<title>John Smith – Medium</title>
			</head><body></body></html>`,
			username: "johnsmith",
			wantName: "John Smith",
		},
		{
			name:     "error page",
			html:     `<html><head><title>Page not found</title></head><body>404</body></html>`,
			username: "missing",
			wantErr:  true,
		},
		{
			name:     "medium only title",
			html:     `<html><head><title>Medium</title></head><body></body></html>`,
			username: "empty",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := parseProfile(tt.html, "https://medium.com/@"+tt.username, tt.username)

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
