package htmlutil

import "testing"

func TestExtractEmailFromURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		wantEmail string
		wantOK    bool
	}{
		{
			name:      "https with email",
			url:       "https://user@example.com",
			wantEmail: "user@example.com",
			wantOK:    true,
		},
		{
			name:      "http with email",
			url:       "http://sanchita.mishra1718@gmail.com",
			wantEmail: "sanchita.mishra1718@gmail.com",
			wantOK:    true,
		},
		{
			name:      "regular https URL",
			url:       "https://example.com",
			wantEmail: "",
			wantOK:    false,
		},
		{
			name:      "email without protocol",
			url:       "user@example.com",
			wantEmail: "",
			wantOK:    false,
		},
		{
			name:      "https with path after email",
			url:       "https://user@example.com/path",
			wantEmail: "user@example.com",
			wantOK:    true,
		},
		{
			name:      "HTTPS uppercase",
			url:       "HTTPS://user@example.com",
			wantEmail: "user@example.com",
			wantOK:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotEmail, gotOK := ExtractEmailFromURL(tt.url)
			if gotEmail != tt.wantEmail {
				t.Errorf("ExtractEmailFromURL(%q) email = %q, want %q", tt.url, gotEmail, tt.wantEmail)
			}
			if gotOK != tt.wantOK {
				t.Errorf("ExtractEmailFromURL(%q) ok = %v, want %v", tt.url, gotOK, tt.wantOK)
			}
		})
	}
}

func TestIsEmailURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"https email", "https://user@example.com", true},
		{"http email", "http://user@example.com", true},
		{"regular URL", "https://example.com", false},
		{"email without protocol", "user@example.com", false},
		{"github URL", "https://github.com/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsEmailURL(tt.url); got != tt.want {
				t.Errorf("IsEmailURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
