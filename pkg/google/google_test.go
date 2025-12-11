package google

import (
	"testing"

	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		// GAIA IDs (21 digits)
		{"118127988220485054809", true},
		{"100000000000000000000", true},
		{"999999999999999999999", true},

		// Gmail addresses
		{"user@gmail.com", true},
		{"user.name@gmail.com", true},
		{"USER@GMAIL.COM", true},
		{"mailto:user@gmail.com", true},
		{"MAILTO:User@Gmail.com", true},

		// Google Maps contrib URLs
		{"https://www.google.com/maps/contrib/118127988220485054809", true},
		{"https://google.com/maps/contrib/118127988220485054809/reviews", true},
		{"http://www.google.com/maps/contrib/100000000000000000000", true},

		// Album archive URLs
		{"https://get.google.com/albumarchive/118127988220485054809", true},
		{"http://get.google.com/albumarchive/100000000000000000000", true},

		// Non-matches
		{"", false},
		{"12345678901234567890", false},   // 20 digits (too short)
		{"1234567890123456789012", false}, // 22 digits (too long)
		{"user@yahoo.com", false},
		{"user@gmail.co", false},
		{"https://google.com/search?q=test", false},
		{"https://maps.google.com/", false},
		{"https://twitter.com/user", false},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := Match(tc.input)
			if got != tc.want {
				t.Errorf("Match(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestExtractArray(t *testing.T) {
	data := []any{
		"level0",
		[]any{
			"level1-0",
			[]any{
				"level2-0",
				"level2-1",
			},
		},
	}

	// Extract [1][1]
	arr := extractArray(data, 1, 1)
	if arr == nil {
		t.Fatal("extractArray returned nil")
	}
	if len(arr) != 2 {
		t.Errorf("expected 2 elements, got %d", len(arr))
	}
	if arr[0] != "level2-0" {
		t.Errorf("expected level2-0, got %v", arr[0])
	}

	// Out of bounds should return nil
	if extractArray(data, 5) != nil {
		t.Error("expected nil for out of bounds")
	}
}

func TestExtractString(t *testing.T) {
	data := []any{
		"level0",
		[]any{
			"level1-0",
			[]any{
				"level2-0",
			},
		},
	}

	// Extract string at [0]
	if s := extractString(data, 0); s != "level0" {
		t.Errorf("expected level0, got %s", s)
	}

	// Extract nested string at [1][1][0]
	if s := extractString(data, 1, 1, 0); s != "level2-0" {
		t.Errorf("expected level2-0, got %s", s)
	}

	// Out of bounds should return empty
	if s := extractString(data, 5); s != "" {
		t.Errorf("expected empty, got %s", s)
	}
}

func TestInferLocation(t *testing.T) {
	tests := []struct {
		name    string
		reviews []profile.Post
		want    string
	}{
		{
			name:    "empty reviews",
			reviews: nil,
			want:    "",
		},
		{
			name: "single review",
			reviews: []profile.Post{
				{Title: "123 Main St, Seattle, WA, USA"},
			},
			want: "WA, USA",
		},
		{
			name: "multiple reviews same location",
			reviews: []profile.Post{
				{Title: "123 Main St, Seattle, WA, USA"},
				{Title: "456 Pike St, Seattle, WA, USA"},
				{Title: "789 Pine St, Seattle, WA, USA"},
			},
			want: "WA, USA",
		},
		{
			name: "mixed locations - most common wins",
			reviews: []profile.Post{
				{Title: "123 Main St, Seattle, WA, USA"},
				{Title: "456 Pike St, Seattle, WA, USA"},
				{Title: "789 Queen St, Toronto, ON, Canada"},
			},
			want: "WA, USA",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := inferLocation(tc.reviews)
			if got != tc.want {
				t.Errorf("inferLocation() = %q, want %q", got, tc.want)
			}
		})
	}
}
