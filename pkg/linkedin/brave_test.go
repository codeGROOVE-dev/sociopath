package linkedin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBraveSearcher(t *testing.T) {
	t.Run("parses_response", func(t *testing.T) {
		// Mock Brave API response
		mockResp := map[string]any{
			"web": map[string]any{
				"results": []map[string]any{
					{
						"title":       "Dan Lorenc - Chainguard, Inc | LinkedIn",
						"url":         "https://www.linkedin.com/in/danlorenc",
						"description": "CEO and co-founder of Chainguard. Based in Barrington. 500+ connections.",
					},
					{
						"title":       "Dan Lorenc on LinkedIn: Some post",
						"url":         "https://www.linkedin.com/posts/danlorenc_something",
						"description": "Some post content.",
					},
				},
			},
		}

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Verify request
			if r.Header.Get("X-Subscription-Token") != "test-key" {
				t.Errorf("expected X-Subscription-Token header")
			}
			if r.Header.Get("Accept") != "application/json" {
				t.Errorf("expected Accept header")
			}
			if r.URL.Query().Get("q") == "" {
				t.Errorf("expected q parameter")
			}

			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(mockResp); err != nil {
				t.Fatalf("encode response: %v", err)
			}
		}))
		defer server.Close()

		// Create searcher with mock server
		searcher := NewBraveSearcher("test-key")
		// Override the endpoint by using a custom transport
		searcher.httpClient.Transport = &mockTransport{
			server: server,
		}

		results, err := searcher.Search(context.Background(), "linkedin.com/in/danlorenc")
		if err != nil {
			t.Fatalf("Search() error = %v", err)
		}

		if len(results) != 2 {
			t.Fatalf("expected 2 results, got %d", len(results))
		}

		if results[0].Title != "Dan Lorenc - Chainguard, Inc | LinkedIn" {
			t.Errorf("unexpected title: %s", results[0].Title)
		}
		if results[0].URL != "https://www.linkedin.com/in/danlorenc" {
			t.Errorf("unexpected URL: %s", results[0].URL)
		}
		if results[0].Snippet != "CEO and co-founder of Chainguard. Based in Barrington. 500+ connections." {
			t.Errorf("unexpected snippet: %s", results[0].Snippet)
		}
	})

	t.Run("handles_error_response", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
			if _, err := w.Write([]byte(`{"error": "invalid api key"}`)); err != nil {
				t.Logf("write error: %v", err)
			}
		}))
		defer server.Close()

		searcher := NewBraveSearcher("bad-key")
		searcher.httpClient.Transport = &mockTransport{server: server}

		_, err := searcher.Search(context.Background(), "test query")
		if err == nil {
			t.Error("expected error for 401 response")
		}
	})
}

// mockTransport redirects all requests to the test server.
type mockTransport struct {
	server *httptest.Server
}

func (m *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Redirect to test server
	req.URL.Scheme = "http"
	req.URL.Host = m.server.Listener.Addr().String()
	return http.DefaultTransport.RoundTrip(req)
}

func TestNewBraveSearcher(t *testing.T) {
	s := NewBraveSearcher("my-api-key")
	if s == nil {
		t.Fatal("NewBraveSearcher returned nil")
	}
	if s.apiKey != "my-api-key" {
		t.Errorf("apiKey = %q, want %q", s.apiKey, "my-api-key")
	}
	if s.httpClient == nil {
		t.Error("httpClient is nil")
	}
}

func TestLoadBraveAPIKey(t *testing.T) {
	t.Run("from_env", func(t *testing.T) {
		t.Setenv("BRAVE_API_KEY", "env-key-123")
		key := LoadBraveAPIKey()
		if key != "env-key-123" {
			t.Errorf("expected env-key-123, got %q", key)
		}
	})

	t.Run("from_file", func(t *testing.T) {
		// Create temp home dir with .brave file
		tmpHome := t.TempDir()
		braveFile := filepath.Join(tmpHome, ".brave")
		if err := os.WriteFile(braveFile, []byte("file-key-456\n"), 0o600); err != nil {
			t.Fatalf("write .brave file: %v", err)
		}

		// Clear env and override home dir
		t.Setenv("BRAVE_API_KEY", "")
		origHome := os.Getenv("HOME")
		t.Setenv("HOME", tmpHome)
		defer func() { t.Setenv("HOME", origHome) }()

		key := LoadBraveAPIKey()
		if key != "file-key-456" {
			t.Errorf("expected file-key-456, got %q", key)
		}
	})

	t.Run("env_takes_precedence", func(t *testing.T) {
		// Create temp home dir with .brave file
		tmpHome := t.TempDir()
		braveFile := filepath.Join(tmpHome, ".brave")
		if err := os.WriteFile(braveFile, []byte("file-key"), 0o600); err != nil {
			t.Fatalf("write .brave file: %v", err)
		}

		// Set both env and file
		t.Setenv("BRAVE_API_KEY", "env-key")
		origHome := os.Getenv("HOME")
		t.Setenv("HOME", tmpHome)
		defer func() { t.Setenv("HOME", origHome) }()

		key := LoadBraveAPIKey()
		if key != "env-key" {
			t.Errorf("expected env-key (precedence), got %q", key)
		}
	})

	t.Run("returns_empty_when_not_found", func(t *testing.T) {
		t.Setenv("BRAVE_API_KEY", "")
		tmpHome := t.TempDir() // Empty dir, no .brave file
		origHome := os.Getenv("HOME")
		t.Setenv("HOME", tmpHome)
		defer func() { t.Setenv("HOME", origHome) }()

		key := LoadBraveAPIKey()
		if key != "" {
			t.Errorf("expected empty string, got %q", key)
		}
	})
}

func TestContainsAnySearchTerm(t *testing.T) {
	tests := []struct {
		name        string
		text        string
		searchTerms string
		want        bool
	}{
		{
			name:        "exact match",
			text:        "works at defenseunicorns",
			searchTerms: "defenseunicorns",
			want:        true,
		},
		{
			name:        "match with spaces in text",
			text:        "works at defense unicorns",
			searchTerms: "defenseunicorns",
			want:        true,
		},
		{
			name:        "no match",
			text:        "works at google",
			searchTerms: "defenseunicorns",
			want:        false,
		},
		{
			name:        "multiple search terms - first matches",
			text:        "defense unicorns is great",
			searchTerms: "defense unicorns",
			want:        true,
		},
		{
			name:        "already lowercase",
			text:        "defense unicorns",
			searchTerms: "defenseunicorns",
			want:        true,
		},
		{
			name:        "empty search terms",
			text:        "anything",
			searchTerms: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := containsAnySearchTerm(tt.text, tt.searchTerms)
			if got != tt.want {
				t.Errorf("containsAnySearchTerm(%q, %q) = %v, want %v",
					tt.text, tt.searchTerms, got, tt.want)
			}
		})
	}
}
