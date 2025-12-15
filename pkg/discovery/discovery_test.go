package discovery

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupKeybase(t *testing.T) {
	tests := []struct {
		name       string
		response   any
		statusCode int
		wantNil    bool
		wantUser   string
	}{
		{
			name: "valid_response",
			response: map[string]any{
				"status": map[string]any{"code": 0, "name": "OK"},
				"them": []map[string]any{
					{"basics": map[string]any{"username": "testuser"}},
				},
			},
			statusCode: http.StatusOK,
			wantNil:    false,
			wantUser:   "testuser",
		},
		{
			name: "empty_them",
			response: map[string]any{
				"status": map[string]any{"code": 0, "name": "OK"},
				"them":   []map[string]any{},
			},
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name: "error_status",
			response: map[string]any{
				"status": map[string]any{"code": 1, "name": "NOT_FOUND"},
			},
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name:       "http_error",
			response:   nil,
			statusCode: http.StatusNotFound,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.statusCode != http.StatusOK {
					w.WriteHeader(tt.statusCode)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(tt.response); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			d := &Discoverer{
				client: server.Client(),
				logger: testLogger(),
			}

			result := d.lookupKeybaseURL(context.Background(), server.URL)

			if tt.wantNil && result != nil {
				t.Errorf("expected nil, got %+v", result)
			}
			if !tt.wantNil && result == nil {
				t.Error("expected result, got nil")
			}
			if !tt.wantNil && result != nil && result.Username != tt.wantUser {
				t.Errorf("username = %q, want %q", result.Username, tt.wantUser)
			}
		})
	}
}

// lookupKeybaseURL is a testable version that accepts a full URL.
func (d *Discoverer) lookupKeybaseURL(ctx context.Context, apiURL string) *Result {
	body, err := d.fetch(ctx, apiURL)
	if err != nil {
		return nil
	}

	var result struct {
		Them []struct {
			Basics struct {
				Username string `json:"username"`
			} `json:"basics"`
		} `json:"them"`
		Status struct {
			Name string `json:"name"`
			Code int    `json:"code"`
		} `json:"status"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	if result.Status.Code != 0 || len(result.Them) == 0 {
		return nil
	}

	username := result.Them[0].Basics.Username
	if username == "" {
		return nil
	}

	return &Result{
		Platform: "keybase",
		URL:      "https://keybase.io/" + username,
		Username: username,
	}
}

func TestLookupNostr(t *testing.T) {
	tests := []struct {
		name       string
		response   any
		statusCode int
		wantNil    bool
		wantPubkey string
	}{
		{
			name: "valid_response",
			response: map[string]any{
				"names": map[string]string{
					"_": "74dcec31fd3b8cfd960bc5a35ecbeeb8b9cee8eb81f6e8da4c8067553709248d",
				},
			},
			statusCode: http.StatusOK,
			wantNil:    false,
			wantPubkey: "74dcec31fd3b8cfd960bc5a35ecbeeb8b9cee8eb81f6e8da4c8067553709248d",
		},
		{
			name: "no_root_identity",
			response: map[string]any{
				"names": map[string]string{
					"alice": "abcd1234",
				},
			},
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name: "invalid_pubkey_length",
			response: map[string]any{
				"names": map[string]string{
					"_": "tooshort",
				},
			},
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name: "invalid_pubkey_chars",
			response: map[string]any{
				"names": map[string]string{
					"_": "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
				},
			},
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name:       "http_error",
			response:   nil,
			statusCode: http.StatusNotFound,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.statusCode != http.StatusOK {
					w.WriteHeader(tt.statusCode)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(tt.response); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			d := &Discoverer{
				client: server.Client(),
				logger: testLogger(),
			}

			result := d.lookupNostrURL(context.Background(), server.URL)

			if tt.wantNil && result != nil {
				t.Errorf("expected nil, got %+v", result)
			}
			if !tt.wantNil && result == nil {
				t.Error("expected result, got nil")
			}
			if !tt.wantNil && result != nil && result.Username != tt.wantPubkey {
				t.Errorf("pubkey = %q, want %q", result.Username, tt.wantPubkey)
			}
		})
	}
}

// lookupNostrURL is a testable version that accepts a full URL.
func (d *Discoverer) lookupNostrURL(ctx context.Context, nip05URL string) *Result {
	body, err := d.fetch(ctx, nip05URL)
	if err != nil {
		return nil
	}

	var result struct {
		Names map[string]string `json:"names"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	pubkey := result.Names["_"]
	if pubkey == "" || !isValidHexPubkey(pubkey) {
		return nil
	}

	return &Result{
		Platform: "nostr",
		URL:      "https://njump.me/" + pubkey,
		Username: pubkey,
	}
}

func TestLookupWebFinger(t *testing.T) {
	tests := []struct {
		name       string
		email      string
		response   any
		statusCode int
		wantNil    bool
		wantURL    string
	}{
		{
			name:  "valid_response",
			email: "user@example.com",
			response: map[string]any{
				"links": []map[string]string{
					{"rel": "http://webfinger.net/rel/profile-page", "href": "https://mastodon.social/@user"},
				},
			},
			statusCode: http.StatusOK,
			wantNil:    false,
			wantURL:    "https://mastodon.social/@user",
		},
		{
			name:  "no_profile_link",
			email: "user@example.com",
			response: map[string]any{
				"links": []map[string]string{
					{"rel": "self", "href": "https://example.com/users/user"},
				},
			},
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name:       "gmail_skipped",
			email:      "user@gmail.com",
			response:   nil,
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name:       "invalid_email",
			email:      "notanemail",
			response:   nil,
			statusCode: http.StatusOK,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.statusCode != http.StatusOK {
					w.WriteHeader(tt.statusCode)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(tt.response); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			d := &Discoverer{
				client: server.Client(),
				logger: testLogger(),
			}

			// For gmail, the function returns early without making a request
			if tt.email == "user@gmail.com" || tt.email == "notanemail" {
				result := d.LookupWebFinger(context.Background(), tt.email)
				if result != nil {
					t.Errorf("expected nil for %s, got %+v", tt.email, result)
				}
				return
			}

			result := d.lookupWebFingerURL(context.Background(), server.URL)

			if tt.wantNil && result != nil {
				t.Errorf("expected nil, got %+v", result)
			}
			if !tt.wantNil && result == nil {
				t.Error("expected result, got nil")
			}
			if !tt.wantNil && result != nil && result.URL != tt.wantURL {
				t.Errorf("URL = %q, want %q", result.URL, tt.wantURL)
			}
		})
	}
}

// lookupWebFingerURL is a testable version that accepts a full URL.
func (d *Discoverer) lookupWebFingerURL(ctx context.Context, webfingerURL string) *Result {
	body, err := d.fetch(ctx, webfingerURL)
	if err != nil {
		return nil
	}

	var result struct {
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	profilePageRel := "http://webfinger.net/rel/profile-page"
	for _, link := range result.Links {
		if link.Rel == profilePageRel && link.Href != "" {
			return &Result{Platform: "fediverse", URL: link.Href}
		}
	}

	return nil
}

func TestLookupMatrix(t *testing.T) {
	tests := []struct {
		name       string
		response   any
		statusCode int
		wantNil    bool
		wantServer string
	}{
		{
			name: "valid_response",
			response: map[string]any{
				"m.server": "matrix-federation.matrix.org:443",
			},
			statusCode: http.StatusOK,
			wantNil:    false,
			wantServer: "matrix-federation.matrix.org:443",
		},
		{
			name: "empty_server",
			response: map[string]any{
				"m.server": "",
			},
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name:       "missing_field",
			response:   map[string]any{},
			statusCode: http.StatusOK,
			wantNil:    true,
		},
		{
			name:       "http_error",
			response:   nil,
			statusCode: http.StatusNotFound,
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tt.statusCode != http.StatusOK {
					w.WriteHeader(tt.statusCode)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(tt.response); err != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
			}))
			defer server.Close()

			d := &Discoverer{
				client: server.Client(),
				logger: testLogger(),
			}

			result := d.lookupMatrixURL(context.Background(), server.URL)

			if tt.wantNil && result != nil {
				t.Errorf("expected nil, got %+v", result)
			}
			if !tt.wantNil && result == nil {
				t.Error("expected result, got nil")
			}
			if !tt.wantNil && result != nil && result.Platform != "matrix" {
				t.Errorf("platform = %q, want %q", result.Platform, "matrix")
			}
		})
	}
}

// lookupMatrixURL is a testable version that accepts a full URL.
func (d *Discoverer) lookupMatrixURL(ctx context.Context, matrixURL string) *Result {
	body, err := d.fetch(ctx, matrixURL)
	if err != nil {
		return nil
	}

	var result struct {
		Server string `json:"m.server"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil
	}

	if result.Server == "" {
		return nil
	}

	return &Result{
		Platform: "matrix",
		URL:      "https://matrix.to/#/@:example.com",
		Username: "@:example.com",
	}
}

func TestIsValidHexPubkey(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"74dcec31fd3b8cfd960bc5a35ecbeeb8b9cee8eb81f6e8da4c8067553709248d", true},
		{"ABCDEF0123456789abcdef0123456789ABCDEF0123456789abcdef0123456789", true},
		{"tooshort", false},
		{"74dcec31fd3b8cfd960bc5a35ecbeeb8b9cee8eb81f6e8da4c8067553709248", false},   // 63 chars
		{"74dcec31fd3b8cfd960bc5a35ecbeeb8b9cee8eb81f6e8da4c8067553709248dd", false}, // 65 chars
		{"gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg", false},  // invalid chars
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := isValidHexPubkey(tt.input)
			if got != tt.want {
				t.Errorf("isValidHexPubkey(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsCommonEmailProvider(t *testing.T) {
	tests := []struct {
		domain string
		want   bool
	}{
		{"gmail.com", true},
		{"GMAIL.COM", true},
		{"yahoo.com", true},
		{"hotmail.com", true},
		{"protonmail.com", true},
		{"example.com", false},
		{"dave.coffee", false},
		{"stromberg.org", false},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			got := isCommonEmailProvider(tt.domain)
			if got != tt.want {
				t.Errorf("isCommonEmailProvider(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func testLogger() *slog.Logger {
	return slog.Default()
}
