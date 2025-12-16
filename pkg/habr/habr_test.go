package habr

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
		{"modern habr.com", "https://habr.com/ru/users/rock", true},
		{"english habr.com", "https://habr.com/en/users/rock", true},
		{"old habrahabr.ru", "http://habrahabr.ru/users/rock", true},
		{"with trailing slash", "https://habr.com/ru/users/rock/", true},
		{"non-profile habr", "https://habr.com/ru/articles/", false},
		{"other domain", "https://example.com/users/rock", false},
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
		{"modern habr", "https://habr.com/ru/users/rock", "rock"},
		{"old habrahabr", "http://habrahabr.ru/users/rock", "rock"},
		{"english habr", "https://habr.com/en/users/someuser", "someuser"},
		{"with trailing slash", "https://habr.com/ru/users/rock/", "rock"},
		{"with query params", "https://habr.com/ru/users/rock?tab=posts", "rock"},
		{"invalid", "https://habr.com/articles/", ""},
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
<title>Rock Developer - JS / Habr</title>
<meta name="description" content="JavaScript developer from Moscow">
</head>
<body>
<dt>About</dt>
<div class="tm-user-profile__content">
<span>Full-stack developer with 10 years of experience</span>
</div>
<dt>Location</dt>
<dd>Moscow, Russia</dd>
<a href="https://github.com/rockdev">GitHub</a>
<a href="https://twitter.com/rockdev">Twitter</a>
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

	profile, err := client.Fetch(ctx, "https://habr.com/en/users/rockdev")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "habr" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "habr")
	}
	if profile.Username != "rockdev" {
		t.Errorf("Username = %q, want %q", profile.Username, "rockdev")
	}
	if profile.DisplayName != "Rock Developer" {
		t.Errorf("Name = %q, want %q", profile.DisplayName, "Rock Developer")
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

	_, err = client.Fetch(ctx, "https://habr.com/en/users/nonexistent")
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

func TestFetch_InvalidUsername(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, "https://habr.com/articles/")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name         string
		html         string
		username     string
		wantName     string
		wantBio      string
		wantLocation string
		wantErr      bool
	}{
		{
			name: "full profile",
			html: `<html><head>
				<title>John Doe - Backend / Habr</title>
			</head><body>
				<dt>About</dt>
				<div class="tm-user-profile__content">
				<span>Senior backend engineer specializing in Go</span>
				</div>
				<dt>Location</dt>
				<dd>Berlin, Germany</dd>
			</body></html>`,
			username:     "johndoe",
			wantName:     "John Doe",
			wantBio:      "Senior backend engineer specializing in Go",
			wantLocation: "Berlin, Germany",
		},
		{
			name: "bio from description",
			html: `<html><head>
				<title>Jane Dev - Habr</title>
				<meta name="description" content="Frontend developer">
			</head><body></body></html>`,
			username: "janedev",
			wantName: "Jane Dev",
			wantBio:  "Frontend developer",
		},
		{
			name: "empty profile",
			html: `<html><head>
				<title></title>
			</head><body></body></html>`,
			username: "empty",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := parseProfile(tt.html, "https://habr.com/en/users/"+tt.username, tt.username)

			if tt.wantErr {
				if err == nil {
					t.Error("parseProfile() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseProfile() error = %v", err)
			}

			if profile.DisplayName != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.DisplayName, tt.wantName)
			}
			if tt.wantBio != "" && profile.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", profile.Bio, tt.wantBio)
			}
			if tt.wantLocation != "" && profile.Location != tt.wantLocation {
				t.Errorf("Location = %q, want %q", profile.Location, tt.wantLocation)
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
