package stackoverflow

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
		{"https://stackoverflow.com/users/12345/johndoe", true},
		{"https://stackoverflow.com/users/12345/john-doe", true},
		{"https://STACKOVERFLOW.COM/users/12345/johndoe", true},
		{"https://stackoverflow.com/questions/123", false},
		{"https://twitter.com/johndoe", false},
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
		t.Error("StackOverflow should not require auth")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://stackoverflow.com/users/12345/johndoe", "johndoe"},
		{"https://stackoverflow.com/users/12345/john-doe", "john-doe"},
		{"https://stackoverflow.com/users/12345/john-doe?tab=profile", "john-doe"},
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
	// Create a mock server that returns StackOverflow-like HTML
	mockHTML := `<!DOCTYPE html>
<html>
<head><title>User Jon Skeet - Stack Overflow</title></head>
<body>
<div class="wmx2 truncate" title="Reading, United Kingdom"></div>
<div class="fs-title">1,234,567</div>
<div>reputation</div>
<a class="post-tag" href="/questions/tagged/c%23">c#</a>
<a class="post-tag" href="/questions/tagged/java">java</a>
<a class="post-tag" href="/questions/tagged/.net">.net</a>
<a href="https://github.com/jskeet">GitHub</a>
<a href="https://twitter.com/jonskeet">Twitter</a>
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

	// Override the httpClient to use our mock server
	client.httpClient = server.Client()

	profile, err := client.Fetch(ctx, server.URL+"/users/22656/jon-skeet")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "stackoverflow" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "stackoverflow")
	}
	if profile.Username != "jon-skeet" {
		t.Errorf("Username = %q, want %q", profile.Username, "jon-skeet")
	}
	if profile.Name != "Jon Skeet" {
		t.Errorf("Name = %q, want %q", profile.Name, "Jon Skeet")
	}
	if profile.Location != "Reading, United Kingdom" {
		t.Errorf("Location = %q, want %q", profile.Location, "Reading, United Kingdom")
	}
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

	_, err = client.Fetch(ctx, server.URL+"/users/999999/nonexistent")
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

func TestParseHTML(t *testing.T) {
	tests := []struct {
		name         string
		html         string
		url          string
		username     string
		wantName     string
		wantLocation string
		wantRep      string
		wantTags     string
	}{
		{
			name: "full profile",
			html: `<html><head><title>User Jon Skeet - Stack Overflow</title></head><body>
				<div class="wmx2 truncate" title="Reading, UK"></div>
				<div class="fs-title">1,234,567</div><div>reputation</div>
				<a class="post-tag">c#</a>
				<a class="post-tag">java</a>
			</body></html>`,
			url:          "https://stackoverflow.com/users/22656/jon-skeet",
			username:     "jon-skeet",
			wantName:     "Jon Skeet",
			wantLocation: "Reading, UK",
			wantRep:      "1,234,567",
			wantTags:     "c#, java",
		},
		{
			name:     "minimal profile",
			html:     `<html><head><title>User newuser - Stack Overflow</title></head><body></body></html>`,
			url:      "https://stackoverflow.com/users/123/newuser",
			username: "newuser",
			wantName: "newuser",
		},
		{
			name:     "no title prefix",
			html:     `<html><head><title>Stack Overflow</title></head><body></body></html>`,
			url:      "https://stackoverflow.com/users/123/someone",
			username: "someone",
			wantName: "someone", // Falls back to username
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := parseHTML([]byte(tt.html), tt.url, tt.username)

			if profile.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.Name, tt.wantName)
			}
			if tt.wantLocation != "" && profile.Location != tt.wantLocation {
				t.Errorf("Location = %q, want %q", profile.Location, tt.wantLocation)
			}
			if tt.wantRep != "" && profile.Fields["reputation"] != tt.wantRep {
				t.Errorf("reputation = %q, want %q", profile.Fields["reputation"], tt.wantRep)
			}
			if tt.wantTags != "" && profile.Fields["top_tags"] != tt.wantTags {
				t.Errorf("top_tags = %q, want %q", profile.Fields["top_tags"], tt.wantTags)
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
