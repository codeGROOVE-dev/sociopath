package stackoverflow

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://stackoverflow.com/users/12345/johndoe", true},
		{"https://stackoverflow.com/users/12345/john-doe", true},
		{"https://STACKOVERFLOW.COM/users/12345/johndoe", true},
		{"https://stackoverflow.com/questions/123", false},
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
		t.Error("StackOverflow should not require auth")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://stackoverflow.com/users/12345/johndoe", "johndoe"},
		{"https://stackoverflow.com/users/12345/john-doe", "john doe"},
		{"https://stackoverflow.com/users/12345/john-doe?tab=profile", "john doe"},
		{"https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractUsername(tt.url)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
