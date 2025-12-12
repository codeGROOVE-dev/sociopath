package htmlutil

import (
	"slices"
	"testing"
)

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
		{"mailto link", "mailto:user@example.com", true},
		{"mailto uppercase", "MAILTO:user@example.com", true},
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

func TestEmailAddresses(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		want    []string
		notWant []string
	}{
		{
			name:    "valid email",
			html:    `<p>Contact me at test@gmail.com</p>`,
			want:    []string{"test@gmail.com"},
			notWant: nil,
		},
		{
			name:    "bogus TLD filtered",
			html:    `<p>u+tko@hrdacmqtem.sqdro</p>`,
			want:    nil,
			notWant: []string{"u+tko@hrdacmqtem.sqdro"},
		},
		{
			name:    "noreply filtered",
			html:    `<p>noreply@example.com</p>`,
			want:    nil,
			notWant: []string{"noreply@example.com"},
		},
		{
			name:    "multiple with bogus filtered",
			html:    `<p>valid@gmail.com and bogus@xyzqw.tklrm</p>`,
			want:    []string{"valid@gmail.com"},
			notWant: []string{"bogus@xyzqw.tklrm"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EmailAddresses(tt.html)
			for _, want := range tt.want {
				if !slices.Contains(got, want) {
					t.Errorf("EmailAddresses() missing %q, got %v", want, got)
				}
			}
			for _, notWant := range tt.notWant {
				if slices.Contains(got, notWant) {
					t.Errorf("EmailAddresses() should not contain %q, got %v", notWant, got)
				}
			}
		})
	}
}
