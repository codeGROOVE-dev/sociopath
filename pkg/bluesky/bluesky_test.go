package bluesky

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
		{"https://bsky.app/profile/johndoe.bsky.social", true},
		{"https://bsky.app/profile/johndoe.com", true},
		{"https://staging.bsky.app/profile/johndoe", true},
		{"https://twitter.com/johndoe", false},
		{"https://mastodon.social/@johndoe", false},
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
		t.Error("BlueSky should not require auth")
	}
}

func TestExtractHandle(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://bsky.app/profile/johndoe.bsky.social", "johndoe.bsky.social"},
		{"https://bsky.app/profile/custom.domain", "custom.domain"},
		{"https://bsky.app/profile/johndoe/posts", "johndoe"},
		{"https://bsky.app/profile/johndoe?tab=likes", "johndoe"},
		{"https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractHandle(tt.url)
			if got != tt.want {
				t.Errorf("extractHandle(%q) = %q, want %q", tt.url, got, tt.want)
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
	mockJSON := `{
		"handle": "jay.bsky.social",
		"displayName": "Jay Graber",
		"description": "CEO @bluesky. Previously @zcikiVP. Building open social.",
		"createdAt": "2021-03-16T00:00:00.000Z"
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(mockJSON)) //nolint:errcheck // test helper
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

	profile, err := client.Fetch(ctx, "https://bsky.app/profile/jay.bsky.social")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "bluesky" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "bluesky")
	}
	if profile.Username != "jay.bsky.social" {
		t.Errorf("Username = %q, want %q", profile.Username, "jay.bsky.social")
	}
	if profile.DisplayName != "Jay Graber" {
		t.Errorf("Name = %q, want %q", profile.DisplayName, "Jay Graber")
	}
	if profile.Bio == "" {
		t.Error("Bio should not be empty")
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

	_, err = client.Fetch(ctx, "https://bsky.app/profile/nonexistent.bsky.social")
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

func TestFetch_InvalidHandle(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, "https://example.com/invalid")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestParseAPIResponse(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		handle       string
		wantName     string
		wantBio      string
		wantHashtags string
		wantErr      bool
	}{
		{
			name: "full profile",
			json: `{
				"handle": "user.bsky.social",
				"displayName": "Test User",
				"description": "Hello world! #bluesky #opensource",
				"createdAt": "2023-01-15T00:00:00.000Z"
			}`,
			handle:       "user.bsky.social",
			wantName:     "Test User",
			wantBio:      "Hello world! #bluesky #opensource",
			wantHashtags: "#bluesky, #opensource",
		},
		{
			name: "minimal profile",
			json: `{
				"handle": "minimal.bsky.social",
				"displayName": "",
				"description": ""
			}`,
			handle:   "minimal.bsky.social",
			wantName: "",
			wantBio:  "",
		},
		{
			name:    "invalid json",
			json:    `{invalid}`,
			handle:  "test",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := parseAPIResponse([]byte(tt.json), "https://bsky.app/profile/"+tt.handle, tt.handle)

			if tt.wantErr {
				if err == nil {
					t.Error("parseAPIResponse() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseAPIResponse() error = %v", err)
			}

			if profile.DisplayName != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.DisplayName, tt.wantName)
			}
			if profile.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", profile.Bio, tt.wantBio)
			}
			if tt.wantHashtags != "" && profile.Fields["hashtags"] != tt.wantHashtags {
				t.Errorf("hashtags = %q, want %q", profile.Fields["hashtags"], tt.wantHashtags)
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
