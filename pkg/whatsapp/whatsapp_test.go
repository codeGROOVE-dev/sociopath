package whatsapp

import (
	"context"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://wa.me/61488999087", true},
		{"https://wa.me/12025551234", true},
		{"https://api.whatsapp.com/send/?phone=61488999087&text&type=phone_number&app_absent=0", true},
		{"https://api.whatsapp.com/send?phone=12025551234", true},
		{"https://whatsapp.com/", false},         // no phone number
		{"https://wa.me/", false},                // no phone number
		{"https://example.com/wa.me/123", false}, // wrong domain
		{"https://twitter.com/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := Match(tt.url); got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractPhone(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://wa.me/61488999087", "61488999087"},
		{"https://wa.me/12025551234", "12025551234"},
		{"https://api.whatsapp.com/send/?phone=61488999087&text&type=phone_number&app_absent=0", "61488999087"},
		{"https://api.whatsapp.com/send?phone=12025551234", "12025551234"},
		{"https://wa.me/", ""},
		{"https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := extractPhone(tt.url); got != tt.want {
				t.Errorf("extractPhone(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestFormatPhone(t *testing.T) {
	tests := []struct {
		phone string
		want  string
	}{
		{"61488999087", "+61 488 999 087"},
		{"12025551234", "+1 202 555 123 4"},
		{"441onal234567", "+44 1on al2 345 67"}, // gibberish but follows pattern
	}

	for _, tt := range tests {
		t.Run(tt.phone, func(t *testing.T) {
			got := formatPhone(tt.phone)
			if got != tt.want {
				t.Errorf("formatPhone(%q) = %q, want %q", tt.phone, got, tt.want)
			}
		})
	}
}

func TestFetch(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		url       string
		wantPhone string
		wantName  string
	}{
		{"https://wa.me/61488999087", "61488999087", "+61 488 999 087"},
		{"https://api.whatsapp.com/send/?phone=61488999087", "61488999087", "+61 488 999 087"},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			p, err := client.Fetch(ctx, tt.url)
			if err != nil {
				t.Fatalf("Fetch(%q) error = %v", tt.url, err)
			}
			if p.Username != tt.wantPhone {
				t.Errorf("Fetch(%q).Username = %q, want %q", tt.url, p.Username, tt.wantPhone)
			}
			if p.DisplayName != tt.wantName {
				t.Errorf("Fetch(%q).DisplayName = %q, want %q", tt.url, p.DisplayName, tt.wantName)
			}
			if p.Platform != "whatsapp" {
				t.Errorf("Fetch(%q).Platform = %q, want %q", tt.url, p.Platform, "whatsapp")
			}
		})
	}
}
