package tiktok

import (
	"context"
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://tiktok.com/@johndoe", true},
		{"https://www.tiktok.com/@johndoe", true},
		{"https://TIKTOK.COM/@johndoe", true},
		{"https://tiktok.com/video/123", false},
		{"https://twitter.com/johndoe", false},
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
		t.Error("TikTok should not require auth")
	}
}

func TestNewWithoutCookies(t *testing.T) {
	client, err := New(context.Background())
	if err != nil {
		t.Errorf("New() without cookies should succeed, got error: %v", err)
	}
	if client == nil {
		t.Error("New() should return a client even without cookies")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"standard url", "https://www.tiktok.com/@dlorenc", "dlorenc"},
		{"without www", "https://tiktok.com/@user123", "user123"},
		{"with query params", "https://www.tiktok.com/@user?foo=bar", "user"},
		{"@mention", "@username", "username"},
		{"bare username", "dlorenc", "dlorenc"},
		{"uppercase", "https://www.tiktok.com/@UserName", "UserName"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractUsername(tt.url)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractUniversalData(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{
			name:    "valid json",
			content: `<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json">{"user":"data"}</script>`,
			want:    `{"user":"data"}`,
		},
		{
			name:    "with attributes",
			content: `<script id="__UNIVERSAL_DATA_FOR_REHYDRATION__" type="application/json" crossorigin="anonymous">{"test":true}</script>`,
			want:    `{"test":true}`,
		},
		{
			name:    "no json",
			content: `<html><body>No script tag here</body></html>`,
			want:    "",
		},
		{
			name:    "wrong id",
			content: `<script id="OTHER_DATA">{"wrong":"data"}</script>`,
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractUniversalData(tt.content)
			if got != tt.want {
				t.Errorf("extractUniversalData() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFilterSamePlatformLinks(t *testing.T) {
	tests := []struct {
		name  string
		links []string
		want  []string
	}{
		{
			name:  "mixed links",
			links: []string{"https://twitter.com/user", "https://www.tiktok.com/@user", "https://github.com/user"},
			want:  []string{"https://twitter.com/user", "https://github.com/user"},
		},
		{
			name:  "all tiktok",
			links: []string{"https://www.tiktok.com/@user1", "https://tiktok.com/@user2"},
			want:  []string{},
		},
		{
			name:  "no tiktok",
			links: []string{"https://twitter.com/user", "https://github.com/user"},
			want:  []string{"https://twitter.com/user", "https://github.com/user"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterSamePlatformLinks(tt.links)
			if len(got) != len(tt.want) {
				t.Errorf("filterSamePlatformLinks() = %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("filterSamePlatformLinks()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
