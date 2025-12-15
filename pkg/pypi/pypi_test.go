package pypi

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
		{"https://pypi.org/user/guido/", true},
		{"https://pypi.org/user/guido", true},
		{"https://PYPI.ORG/user/guido/", true},
		{"https://pypi.org/user/guido/?tab=packages", true},
		{"https://pypi.org/project/mypy/", false}, // project page, not profile
		{"https://pypi.org/", false},              // homepage
		{"https://github.com/guido", false},       // wrong platform
		{"https://example.com", false},            // unrelated
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
		t.Error("PyPI should not require auth")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://pypi.org/user/guido/", "guido"},
		{"https://pypi.org/user/guido", "guido"},
		{"https://pypi.org/user/GvR/", "GvR"},
		{"https://pypi.org/user/some-user?tab=packages", "some-user"},
		{"https://example.com", ""},
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
<head><title>Profile of guido · PyPI</title></head>
<body>
<h1 class="author-profile__name">Guido van Rossum</h1>
<img src="https://example.com/avatar.png" alt="Avatar for guido">
<h2>12 projects</h2>
<a class="package-snippet" href="/project/mypy/">
<h3 class="package-snippet__title">mypy</h3>
<p class="package-snippet__description">Optional static typing for Python</p>
</a>
<a class="package-snippet" href="/project/asyncio/">
<h3 class="package-snippet__title">asyncio</h3>
<p class="package-snippet__description">Deprecated backport of asyncio</p>
</a>
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
	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	profile, err := client.Fetch(ctx, "https://pypi.org/user/guido/")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "pypi" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "pypi")
	}
	if profile.Username != "guido" {
		t.Errorf("Username = %q, want %q", profile.Username, "guido")
	}
	if profile.Name != "Guido van Rossum" {
		t.Errorf("Name = %q, want %q", profile.Name, "Guido van Rossum")
	}
	if profile.Fields["projects"] != "12" {
		t.Errorf("projects = %q, want %q", profile.Fields["projects"], "12")
	}
	if len(profile.Posts) != 2 {
		t.Fatalf("Posts count = %d, want 2", len(profile.Posts))
	}
	if profile.Posts[0].Title != "mypy" {
		t.Errorf("First post title = %q, want %q", profile.Posts[0].Title, "mypy")
	}
}

type mockTransport struct {
	mockURL string
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "http"
	req.URL.Host = m.mockURL[7:] // Strip "http://"
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
	client.httpClient = server.Client()

	_, err = client.Fetch(ctx, server.URL+"/user/nonexistent/")
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

	_, err = client.Fetch(ctx, "https://example.com/notpypi")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestParseHTML(t *testing.T) {
	tests := []struct {
		name         string
		html         string
		username     string
		wantName     string
		wantProjects string
		wantPostCnt  int
	}{
		{
			name: "full profile",
			html: `<html>
				<h1 class="author-profile__name">Test User</h1>
				<h2>5 projects</h2>
				<a class="package-snippet" href="/project/pkg1/">
				<h3 class="package-snippet__title">pkg1</h3>
				<p class="package-snippet__description">Package 1</p>
				</a>
			</html>`,
			username:     "testuser",
			wantName:     "Test User",
			wantProjects: "5",
			wantPostCnt:  1,
		},
		{
			name: "single project",
			html: `<html>
				<h1 class="author-profile__name">Dev</h1>
				<h2>1 project</h2>
			</html>`,
			username:     "dev",
			wantName:     "Dev",
			wantProjects: "1",
			wantPostCnt:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := parseHTML([]byte(tt.html), "https://pypi.org/user/"+tt.username+"/", tt.username)

			if profile.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.Name, tt.wantName)
			}
			if tt.wantProjects != "" && profile.Fields["projects"] != tt.wantProjects {
				t.Errorf("projects = %q, want %q", profile.Fields["projects"], tt.wantProjects)
			}
			if len(profile.Posts) != tt.wantPostCnt {
				t.Errorf("Posts count = %d, want %d", len(profile.Posts), tt.wantPostCnt)
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
