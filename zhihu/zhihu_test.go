package zhihu

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"people URL", "https://zhihu.com/people/username", true},
		{"www variant", "https://www.zhihu.com/people/username", true},
		{"with path", "https://zhihu.com/people/username/answers", true},
		{"question URL", "https://zhihu.com/question/12345", false},
		{"other domain", "https://weibo.com/user", false},
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
		{"standard", "https://zhihu.com/people/username", "username"},
		{"www variant", "https://www.zhihu.com/people/user123", "user123"},
		{"with path", "https://zhihu.com/people/username/answers", "username"},
		{"invalid", "https://zhihu.com/question/123", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractUsername(tt.url); got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}
