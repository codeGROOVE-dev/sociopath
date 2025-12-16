package linkedin

import (
	"context"
	"log/slog"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://www.linkedin.com/in/johndoe", true},
		{"https://linkedin.com/in/johndoe", true},
		{"https://linkedin.com/in/johndoe/", true},
		{"linkedin.com/in/johndoe", true},
		{"https://LINKEDIN.COM/IN/johndoe", true},
		{"https://linkedin.com/company/acme", false},
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
	if !AuthRequired() {
		t.Error("LinkedIn should require auth")
	}
}

func TestExtractPublicID(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://linkedin.com/in/johndoe", "johndoe"},
		{"https://linkedin.com/in/johndoe/", "johndoe"},
		{"https://linkedin.com/in/john-doe-123", "john-doe-123"},
		{"https://www.linkedin.com/in/ariadneconill/", "ariadneconill"},
		{"https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractPublicID(tt.url)
			if got != tt.want {
				t.Errorf("extractPublicID(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsDirectProfileURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://www.linkedin.com/in/danlorenc", true},
		{"https://www.linkedin.com/in/danlorenc/", true},
		{"https://linkedin.com/in/reidhoffman", true},
		{"https://www.linkedin.com/in/ariadneconill/posts", false},
		{"https://www.linkedin.com/in/ariadneconill/activity", false},
		{"https://www.linkedin.com/posts/danlorenc_docker-activity-123", false},
		{"https://www.linkedin.com/pub/dir/Linus/Torvalds", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := isDirectProfileURL(tt.url)
			if got != tt.want {
				t.Errorf("isDirectProfileURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseTitle(t *testing.T) {
	tests := []struct {
		title        string
		wantName     string
		wantHeadline string
	}{
		{
			"Dan Lorenc - Chainguard, Inc | LinkedIn",
			"Dan Lorenc", "Chainguard, Inc",
		},
		{
			"Linus Torvalds - Linux Foundation | LinkedIn",
			"Linus Torvalds", "Linux Foundation",
		},
		{
			"Reid Hoffman - Co-Founder, LinkedIn, Manas AI & Inflection AI. Founding Team, PayPal. | LinkedIn",
			"Reid Hoffman", "Co-Founder, LinkedIn, Manas AI & Inflection AI. Founding Team, PayPal.",
		},
		{
			"Ariadne Conill - Edera | LinkedIn",
			"Ariadne Conill", "Edera",
		},
		{
			"John Doe | LinkedIn",
			"John Doe", "",
		},
		{
			"Jane Smith - LinkedIn",
			"Jane Smith", "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.title, func(t *testing.T) {
			name, headline := parseTitle(tt.title)
			if name != tt.wantName {
				t.Errorf("parseTitle(%q) name = %q, want %q", tt.title, name, tt.wantName)
			}
			if headline != tt.wantHeadline {
				t.Errorf("parseTitle(%q) headline = %q, want %q", tt.title, headline, tt.wantHeadline)
			}
		})
	}
}

func TestExtractCompany(t *testing.T) {
	tests := []struct {
		headline string
		want     string
	}{
		{"Chainguard, Inc", "Chainguard, Inc"},
		{"Linux Foundation", "Linux Foundation"},
		{"Edera", "Edera"},
		{"CEO at Acme Corp", "Acme Corp"},
		{"Software Engineer @ Google", "Google"},
		{"Founder, StartupXYZ", "StartupXYZ"},
		{"Director of Engineering at Meta", "Meta"},
		{"Co-Founder, LinkedIn, Manas AI & Inflection AI. Founding Team, PayPal.", "LinkedIn"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.headline, func(t *testing.T) {
			got := extractCompany(tt.headline)
			if got != tt.want {
				t.Errorf("extractCompany(%q) = %q, want %q", tt.headline, got, tt.want)
			}
		})
	}
}

func TestExtractLocation(t *testing.T) {
	tests := []struct {
		snippet string
		want    string
	}{
		{"Based in Seattle, WA.", "Seattle"},         // stops at comma
		{"Located in Portland, Oregon.", "Portland"}, // stops at comma
		{"CEO of Acme Corp. Location: San Francisco", "San Francisco"},
		{"No location info here.", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.snippet, func(t *testing.T) {
			got := extractLocation(tt.snippet)
			if got != tt.want {
				t.Errorf("extractLocation(%q) = %q, want %q", tt.snippet, got, tt.want)
			}
		})
	}
}

func TestExtractEducation(t *testing.T) {
	tests := []struct {
		snippet string
		want    string
	}{
		{"Graduate of Massachusetts Institute of Technology. CEO of Acme.", "Massachusetts Institute of Technology"},
		{"Studied at Stanford. Now working at Google.", "Stanford"},
		{"Attended Harvard University, class of 2010.", "Harvard University"},
		{"Graduated from UC Berkeley. Works at Google.", "UC Berkeley"},
		{"No education info here.", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.snippet, func(t *testing.T) {
			got := extractEducation(tt.snippet)
			if got != tt.want {
				t.Errorf("extractEducation(%q) = %q, want %q", tt.snippet, got, tt.want)
			}
		})
	}
}

func TestExtractConnections(t *testing.T) {
	tests := []struct {
		snippet string
		want    string
	}{
		{"500+ connections on LinkedIn.", "500"},
		{"Has 263 connections.", "263"},
		{"1000 connections in network.", "1000"},
		{"No connection info.", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.snippet, func(t *testing.T) {
			got := extractConnections(tt.snippet)
			if got != tt.want {
				t.Errorf("extractConnections(%q) = %q, want %q", tt.snippet, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()

	t.Run("creates_client_without_error", func(t *testing.T) {
		client, err := New(ctx)
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}
		if client == nil {
			t.Fatal("New() returned nil client")
		}
	})

	t.Run("with_logger", func(t *testing.T) {
		logger := slog.New(slog.DiscardHandler)
		client, err := New(ctx, WithLogger(logger))
		if err != nil {
			t.Fatalf("New(WithLogger) failed: %v", err)
		}
		if client == nil {
			t.Fatal("New(WithLogger) returned nil client")
		}
	})
}

func TestFetch(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)
	client, err := New(ctx, WithLogger(logger))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	t.Run("returns_minimal_profile", func(t *testing.T) {
		prof, err := client.Fetch(ctx, "https://www.linkedin.com/in/johndoe")
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if prof == nil {
			t.Fatal("Fetch() returned nil profile")
		}
		if prof.Platform != "linkedin" {
			t.Errorf("Platform = %q, want %q", prof.Platform, "linkedin")
		}
		if prof.Username != "johndoe" {
			t.Errorf("Username = %q, want %q", prof.Username, "johndoe")
		}
		if prof.URL != "https://www.linkedin.com/in/johndoe" {
			t.Errorf("URL = %q, want %q", prof.URL, "https://www.linkedin.com/in/johndoe")
		}
		if prof.Authenticated {
			t.Error("Authenticated should be false")
		}
	})

	t.Run("normalizes_url", func(t *testing.T) {
		prof, err := client.Fetch(ctx, "johndoe")
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if prof.URL != "https://www.linkedin.com/in/johndoe" {
			t.Errorf("URL = %q, want normalized URL", prof.URL)
		}
	})
}

// mockSearcher implements Searcher for testing.
type mockSearcher struct {
	results []SearchResult
	err     error
}

func (m *mockSearcher) Search(_ context.Context, _ string) ([]SearchResult, error) {
	return m.results, m.err
}

func TestFetchWithSearcher(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	t.Run("extracts_profile_from_search", func(t *testing.T) {
		searcher := &mockSearcher{
			results: []SearchResult{
				{
					Title:   "Dan Lorenc - Chainguard, Inc | LinkedIn",
					URL:     "https://www.linkedin.com/in/danlorenc",
					Snippet: "CEO and co-founder of Chainguard. Graduate of Massachusetts Institute of Technology. Based in Barrington. 500+ connections.",
				},
			},
		}

		client, err := New(ctx, WithLogger(logger), WithSearcher(searcher))
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		prof, err := client.Fetch(ctx, "https://www.linkedin.com/in/danlorenc")
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}

		if prof.DisplayName != "Dan Lorenc" {
			t.Errorf("DisplayName = %q, want %q", prof.DisplayName, "Dan Lorenc")
		}
		if prof.Bio != "Chainguard, Inc" {
			t.Errorf("Bio = %q, want %q", prof.Bio, "Chainguard, Inc")
		}
		if prof.Fields["company"] != "Chainguard, Inc" {
			t.Errorf("Fields[company] = %q, want %q", prof.Fields["company"], "Chainguard, Inc")
		}
		if prof.Location != "Barrington" {
			t.Errorf("Location = %q, want %q", prof.Location, "Barrington")
		}
		if prof.Fields["education"] != "Massachusetts Institute of Technology" {
			t.Errorf("Fields[education] = %q, want %q", prof.Fields["education"], "Massachusetts Institute of Technology")
		}
		if prof.Fields["connections"] != "500" {
			t.Errorf("Fields[connections] = %q, want %q", prof.Fields["connections"], "500")
		}
	})

	t.Run("filters_non_profile_urls", func(t *testing.T) {
		searcher := &mockSearcher{
			results: []SearchResult{
				{
					Title:   "Dan Lorenc on LinkedIn: Some post about Docker",
					URL:     "https://www.linkedin.com/posts/danlorenc_docker-activity-123",
					Snippet: "Some post content.",
				},
				{
					Title:   "Dan Lorenc - Chainguard, Inc | LinkedIn",
					URL:     "https://www.linkedin.com/in/danlorenc",
					Snippet: "CEO of Chainguard.",
				},
			},
		}

		client, err := New(ctx, WithLogger(logger), WithSearcher(searcher))
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		prof, err := client.Fetch(ctx, "https://www.linkedin.com/in/danlorenc")
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}

		// Should use the second result (direct profile URL)
		if prof.DisplayName != "Dan Lorenc" {
			t.Errorf("DisplayName = %q, want %q", prof.DisplayName, "Dan Lorenc")
		}
	})

	t.Run("falls_back_to_minimal_on_empty_results", func(t *testing.T) {
		searcher := &mockSearcher{
			results: []SearchResult{},
		}

		client, err := New(ctx, WithLogger(logger), WithSearcher(searcher))
		if err != nil {
			t.Fatalf("New() failed: %v", err)
		}

		prof, err := client.Fetch(ctx, "https://www.linkedin.com/in/unknown")
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}

		// Should return minimal profile
		if prof.Username != "unknown" {
			t.Errorf("Username = %q, want %q", prof.Username, "unknown")
		}
		if prof.DisplayName != "" {
			t.Errorf("DisplayName should be empty for minimal profile, got %q", prof.DisplayName)
		}
	})
}
