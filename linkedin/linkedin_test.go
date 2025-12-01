package linkedin

import (
	"context"
	"io"
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

func TestParseCompanyFromHeadline(t *testing.T) {
	tests := []struct {
		headline string
		want     string
	}{
		{"Software Engineer at Google", "Google"},
		{"CEO @ Startup", "Startup"},
		{"Engineering @Akuity", "Akuity"},
		{"Engineer, Acme Corp", ""},  // comma-separated formats are too ambiguous (e.g., "P2P, Rust")
		{"Senior Developer at Meta, Inc.", "Meta"},
		{"Just a person", ""},
	}

	for _, tt := range tests {
		t.Run(tt.headline, func(t *testing.T) {
			got := parseCompanyFromHeadline(tt.headline)
			if got != tt.want {
				t.Errorf("parseCompanyFromHeadline(%q) = %q, want %q", tt.headline, got, tt.want)
			}
		})
	}
}

func TestExtractJSONField(t *testing.T) {
	json := `{"firstName":"John","lastName":"Doe","headline":"Engineer"}`

	tests := []struct {
		field string
		want  string
	}{
		{"firstName", "John"},
		{"lastName", "Doe"},
		{"headline", "Engineer"},
		{"missing", ""},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got := extractJSONField(json, tt.field)
			if got != tt.want {
				t.Errorf("extractJSONField(%q) = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

func TestUnescapeJSON(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{`hello\nworld`, "hello\nworld"},
		{`Tom \u0026 Jerry`, "Tom & Jerry"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := unescapeJSON(tt.input)
			if got != tt.want {
				t.Errorf("unescapeJSON(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()

	t.Run("default_requires_auth", func(t *testing.T) {
		_, err := New(ctx)
		if err == nil {
			t.Fatal("New() should fail without authentication")
		}
		if !AuthRequired() {
			t.Error("AuthRequired() should return true for LinkedIn")
		}
	})

	t.Run("with_cookies", func(t *testing.T) {
		// Test that WithCookies option is accepted with dummy cookies
		dummyCookies := map[string]string{
			"LINKEDIN_LI_AT":      "dummy",
			"LINKEDIN_JSESSIONID": "dummy",
			"LINKEDIN_LIDC":       "dummy",
			"LINKEDIN_BCOOKIE":    "dummy",
		}
		client, err := New(ctx, WithCookies(dummyCookies))
		if err != nil {
			t.Fatalf("New(WithCookies) failed: %v", err)
		}
		if client == nil {
			t.Fatal("New(WithCookies) returned nil client")
		}
	})

	t.Run("with_logger", func(t *testing.T) {
		logger := slog.New(slog.NewTextHandler(io.Discard, nil))
		// LinkedIn still requires cookies even with logger
		dummyCookies := map[string]string{
			"LINKEDIN_LI_AT":      "dummy",
			"LINKEDIN_JSESSIONID": "dummy",
			"LINKEDIN_LIDC":       "dummy",
			"LINKEDIN_BCOOKIE":    "dummy",
		}
		client, err := New(ctx, WithLogger(logger), WithCookies(dummyCookies))
		if err != nil {
			t.Fatalf("New(WithLogger, WithCookies) failed: %v", err)
		}
		if client == nil {
			t.Fatal("New(WithLogger, WithCookies) returned nil client")
		}
	})
}

func TestParseProfileCanonicalizesRedirectedURL(t *testing.T) {
	// When LinkedIn redirects an old profile URL to a new one,
	// we should update the URL to the canonical form based on the
	// actual username returned. This helps with deduplication.

	// Minimal HTML that parseProfile can extract data from
	html := `<!DOCTYPE html>
<html>
<head><title>Thomas Strömberg | LinkedIn</title></head>
<body>
<code id="bpr-guid-123">{"publicIdentifier":"thomrstrom","firstName":"Thomas","lastName":"Strömberg"}</code>
</body>
</html>`

	// Request old URL but get profile for thomrstrom
	requestedURL := "https://www.linkedin.com/in/thomas-stromberg-9977261/"
	prof, err := parseProfile([]byte(html), requestedURL)
	if err != nil {
		t.Fatalf("parseProfile failed: %v", err)
	}

	// URL should be canonicalized to the actual username
	expectedURL := "https://www.linkedin.com/in/thomrstrom"
	if prof.URL != expectedURL {
		t.Errorf("parseProfile URL = %q, want %q (should canonicalize on redirect)", prof.URL, expectedURL)
	}

	// Username should be the actual username from the response
	if prof.Username != "thomrstrom" {
		t.Errorf("parseProfile Username = %q, want %q", prof.Username, "thomrstrom")
	}
}

func TestParseProfileKeepsURLWhenMatching(t *testing.T) {
	// When the requested URL matches the returned profile, keep the original URL

	html := `<!DOCTYPE html>
<html>
<head><title>John Doe | LinkedIn</title></head>
<body>
<code id="bpr-guid-123">{"publicIdentifier":"johndoe","firstName":"John","lastName":"Doe"}</code>
</body>
</html>`

	requestedURL := "https://www.linkedin.com/in/johndoe"
	prof, err := parseProfile([]byte(html), requestedURL)
	if err != nil {
		t.Fatalf("parseProfile failed: %v", err)
	}

	// URL should remain as requested since it matches
	if prof.URL != requestedURL {
		t.Errorf("parseProfile URL = %q, want %q (should keep original when matching)", prof.URL, requestedURL)
	}
}
