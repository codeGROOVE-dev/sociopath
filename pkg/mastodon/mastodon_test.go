package mastodon

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
		{"https://mastodon.social/@johndoe", true},
		{"https://fosstodon.org/@johndoe", true},
		{"https://hachyderm.io/@johndoe", true},
		{"https://infosec.exchange/@johndoe", true},
		{"https://example.social/@johndoe", true},
		{"https://mastodon.social/users/johndoe", true},
		{"https://twitter.com/johndoe", false},
		{"https://linkedin.com/in/johndoe", false},
		{"https://example.com/about", false},
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
		t.Error("Mastodon should not require auth")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/@johndoe", "johndoe"},
		{"/users/johndoe", "johndoe"},
		{"/@johndoe/followers", "johndoe"},
		{"/about", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := extractUsername(tt.path)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestStripHTML(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "basic paragraph",
			input: "<p>Hello</p>",
			want:  "Hello",
		},
		{
			name:  "multiple paragraphs",
			input: "<p>Hello</p><p>World</p>",
			want:  "Hello\nWorld",
		},
		{
			name:  "HTML entities",
			input: "Hello &amp; World",
			want:  "Hello & World",
		},
		{
			name:  "links",
			input: "<a href='url'>link</a>",
			want:  "link",
		},
		{
			name:  "br tag",
			input: "Line 1<br>Line 2",
			want:  "Line 1\nLine 2",
		},
		{
			name:  "br self-closing",
			input: "Line 1<br/>Line 2",
			want:  "Line 1\nLine 2",
		},
		{
			name:  "br with space",
			input: "Line 1<br />Line 2",
			want:  "Line 1\nLine 2",
		},
		{
			name:  "div tags",
			input: "<div>Block 1</div><div>Block 2</div>",
			want:  "Block 1\nBlock 2",
		},
		{
			name:  "complex bio with multiple breaks",
			input: "KD4UHP - based out of Carrboro, NC<br>founder &amp; CEO @ codeGROOVE<br />former Director of Security @ Chainguard &amp; Xoogler<br/>#unix #infosec #bikes",
			want:  "KD4UHP - based out of Carrboro, NC\nfounder & CEO @ codeGROOVE\nformer Director of Security @ Chainguard & Xoogler\n#unix #infosec #bikes",
		},
		{
			name:  "empty lines removed",
			input: "<p>Line 1</p><p></p><p>Line 2</p>",
			want:  "Line 1\nLine 2",
		},
		{
			name:  "whitespace normalized",
			input: "<p>  Line 1  </p><br/><p>   Line 2   </p>",
			want:  "Line 1\nLine 2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripHTML(tt.input)
			if got != tt.want {
				t.Errorf("stripHTML(%q) = %q, want %q", tt.input, got, tt.want)
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

func TestFetch_ViaAPI(t *testing.T) {
	mockJSON := `{
		"username": "Gargron",
		"display_name": "Eugen Rochko",
		"note": "<p>Developer of Mastodon</p>",
		"created_at": "2016-03-16T00:00:00.000Z",
		"fields": [
			{"name": "Location", "value": "Germany"},
			{"name": "Website", "value": "<a href=\"https://joinmastodon.org\">joinmastodon.org</a>"}
		]
	}`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle API lookup request
		if r.URL.Path == "/api/v1/accounts/lookup" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockJSON)) //nolint:errcheck // test helper
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Create a custom transport that redirects all requests to our test server
	client.httpClient = &http.Client{
		Transport: &mockTransport{mockURL: server.URL},
	}

	profile, err := client.Fetch(ctx, "https://mastodon.social/@Gargron")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "mastodon" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "mastodon")
	}
	if profile.Username != "Gargron" {
		t.Errorf("Username = %q, want %q", profile.Username, "Gargron")
	}
	if profile.Name != "Eugen Rochko" {
		t.Errorf("Name = %q, want %q", profile.Name, "Eugen Rochko")
	}
	if profile.Location != "Germany" {
		t.Errorf("Location = %q, want %q", profile.Location, "Germany")
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

func TestFetch_ViaHTML(t *testing.T) {
	mockHTML := `<!DOCTYPE html>
<html>
<head>
<title>@johndoe - Mastodon</title>
<meta name="description" content="Hello, I'm John Doe">
</head>
<body>
<a href="https://github.com/johndoe">GitHub</a>
</body>
</html>`

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/accounts/lookup" {
			w.WriteHeader(http.StatusNotFound) // API fails
		} else {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(mockHTML)) //nolint:errcheck // test helper
		}
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	client.httpClient = server.Client()

	profile, err := client.Fetch(ctx, server.URL+"/@johndoe")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "mastodon" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "mastodon")
	}
	if profile.Username != "johndoe" {
		t.Errorf("Username = %q, want %q", profile.Username, "johndoe")
	}
}

func TestFetch_InvalidURL(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, "://invalid")
	if err == nil {
		t.Error("Fetch() expected error for invalid URL, got nil")
	}
}

func TestFetch_InvalidUsername(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, "https://mastodon.social/about")
	if err == nil {
		t.Error("Fetch() expected error for invalid username, got nil")
	}
}

func TestParseAPIResponse(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		wantUsername string
		wantName     string
		wantLocation string
		wantErr      bool
	}{
		{
			name: "full profile",
			json: `{
				"username": "user1",
				"display_name": "User One",
				"note": "<p>Hello world</p>",
				"fields": [{"name": "Location", "value": "NYC"}]
			}`,
			wantUsername: "user1",
			wantName:     "User One",
			wantLocation: "NYC",
		},
		{
			name: "city field",
			json: `{
				"username": "user2",
				"display_name": "User Two",
				"note": "",
				"fields": [{"name": "City", "value": "London"}]
			}`,
			wantUsername: "user2",
			wantName:     "User Two",
			wantLocation: "London",
		},
		{
			name:    "invalid json",
			json:    `{invalid}`,
			wantErr: true,
		},
	}

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prof, _, err := client.parseAPIResponse([]byte(tt.json))

			if tt.wantErr {
				if err == nil {
					t.Error("parseAPIResponse() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseAPIResponse() error = %v", err)
			}

			if prof.Username != tt.wantUsername {
				t.Errorf("Username = %q, want %q", prof.Username, tt.wantUsername)
			}
			if prof.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", prof.Name, tt.wantName)
			}
			if tt.wantLocation != "" && prof.Location != tt.wantLocation {
				t.Errorf("Location = %q, want %q", prof.Location, tt.wantLocation)
			}
		})
	}
}

func TestExtractURLs(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{
			name:  "single url",
			input: `<a href="https://example.com">link</a>`,
			want:  1,
		},
		{
			name:  "multiple urls",
			input: `<a href="https://example.com">one</a> <a href="https://github.com/user">two</a>`,
			want:  2,
		},
		{
			name:  "no urls",
			input: `plain text`,
			want:  0,
		},
		{
			name:  "relative url ignored",
			input: `<a href="/about">about</a>`,
			want:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			urls := extractURLs(tt.input)
			if len(urls) != tt.want {
				t.Errorf("extractURLs() returned %d urls, want %d", len(urls), tt.want)
			}
		})
	}
}

func TestFilterSameServerLinks(t *testing.T) {
	links := []string{
		"https://mastodon.social/@other",
		"https://github.com/user",
		"https://twitter.com/user",
	}

	filtered := filterSameServerLinks(links, "https://mastodon.social/@me")

	// Should filter out the mastodon.social link
	if len(filtered) != 2 {
		t.Errorf("filterSameServerLinks() returned %d links, want 2", len(filtered))
	}

	for _, link := range filtered {
		if link == "https://mastodon.social/@other" {
			t.Error("filterSameServerLinks() should have filtered same-server mastodon link")
		}
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
