package youtube

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
		{"handle format", "https://youtube.com/@username", true},
		{"channel ID", "https://youtube.com/channel/UCxxxxxx", true},
		{"c/ format", "https://youtube.com/c/ChannelName", true},
		{"user format", "https://youtube.com/user/username", true},
		{"www variant", "https://www.youtube.com/@handle", true},
		{"video URL", "https://youtube.com/watch?v=xxxxx", false},
		{"other domain", "https://vimeo.com/user", false},
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
		{"handle", "https://youtube.com/@johndoe", "johndoe"},
		{"channel ID", "https://youtube.com/channel/UC123456", "UC123456"},
		{"c/ format", "https://youtube.com/c/MyChannel", "MyChannel"},
		{"user format", "https://youtube.com/user/olduser", "olduser"},
		{"with www", "https://www.youtube.com/@testuser", "testuser"},
		{"with query", "https://youtube.com/@user?sub=1", "user"},
		{"invalid", "https://youtube.com/watch", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsDefaultBio(t *testing.T) {
	tests := []struct {
		name string
		bio  string
		want bool
	}{
		{"default bio", "Share your videos with friends, family, and the world", true},
		{"default bio with caps", "SHARE YOUR VIDEOS WITH FRIENDS, FAMILY, AND THE WORLD", true},
		{"default bio with whitespace", "  Share your videos with friends, family, and the world  ", true},
		{"custom bio", "Tech tutorials and coding content", false},
		{"similar but not default", "Share your videos with friends", false},
		{"empty bio", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDefaultBio(tt.bio); got != tt.want {
				t.Errorf("isDefaultBio(%q) = %v, want %v", tt.bio, got, tt.want)
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
<title>Tech Channel - YouTube</title>
<meta name="description" content="Coding tutorials and tech reviews">
</head>
<body>
<span>1.5M subscribers</span>
<span>500 videos</span>
<a href="https://twitter.com/techchannel">Twitter</a>
<a href="https://github.com/techchannel">GitHub</a>
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

	profile, err := client.Fetch(ctx, "https://www.youtube.com/@techchannel")
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}

	if profile.Platform != "youtube" {
		t.Errorf("Platform = %q, want %q", profile.Platform, "youtube")
	}
	if profile.Username != "techchannel" {
		t.Errorf("Username = %q, want %q", profile.Username, "techchannel")
	}
	if profile.Name != "Tech Channel" {
		t.Errorf("Name = %q, want %q", profile.Name, "Tech Channel")
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

	_, err = client.Fetch(ctx, "https://www.youtube.com/@nonexistent")
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

func TestParseProfile(t *testing.T) {
	tests := []struct {
		name            string
		html            string
		url             string
		wantName        string
		wantBio         string
		wantSubscribers string
	}{
		{
			name: "full profile",
			html: `<html><head>
				<title>My Channel - YouTube</title>
				<meta name="description" content="Welcome to my channel">
			</head><body>
				<span>100K subscribers</span>
				<span>200 videos</span>
			</body></html>`,
			url:             "https://youtube.com/@mychannel",
			wantName:        "My Channel",
			wantBio:         "Welcome to my channel",
			wantSubscribers: "100K",
		},
		{
			name: "default bio filtered",
			html: `<html><head>
				<title>New Channel - YouTube</title>
				<meta name="description" content="Share your videos with friends, family, and the world">
			</head><body></body></html>`,
			url:      "https://youtube.com/@newchannel",
			wantName: "New Channel",
			wantBio:  "",
		},
		{
			name: "fallback to username",
			html: `<html><head>
				<title></title>
			</head><body></body></html>`,
			url:      "https://youtube.com/@fallbackuser",
			wantName: "fallbackuser",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := parseProfile(tt.html, tt.url)
			if err != nil {
				t.Fatalf("parseProfile() error = %v", err)
			}

			if profile.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.Name, tt.wantName)
			}
			if profile.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", profile.Bio, tt.wantBio)
			}
			if tt.wantSubscribers != "" && profile.Fields["subscribers"] != tt.wantSubscribers {
				t.Errorf("subscribers = %q, want %q", profile.Fields["subscribers"], tt.wantSubscribers)
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
