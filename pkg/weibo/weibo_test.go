//nolint:gosmopolitan // Chinese platform requires Chinese characters in tests
package weibo

import (
	"testing"
)

func TestMatch(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		{"weibo.com profile", "https://weibo.com/dryuanchen", true},
		{"weibo.com with www", "https://www.weibo.com/dryuanchen", true},
		{"weibo.com with uid", "https://weibo.com/u/6974787068", true},
		{"weibo.cn mobile", "https://weibo.cn/dryuanchen", true},
		{"http scheme", "http://weibo.com/testuser", true},
		{"uppercase", "https://WEIBO.COM/testuser", true},
		{"other domain", "https://twitter.com/testuser", false},
		{"similar domain", "https://notweibo.com/user", false},
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
	if !AuthRequired() {
		t.Error("AuthRequired() = false, want true")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want string
	}{
		{"username", "https://weibo.com/dryuanchen", "dryuanchen"},
		{"username with www", "https://www.weibo.com/dryuanchen", "dryuanchen"},
		{"uid format", "https://weibo.com/u/6974787068", "6974787068"},
		{"mobile", "https://weibo.cn/testuser", "testuser"},
		{"with query", "https://weibo.com/testuser?from=feed", "testuser"},
		{"with fragment", "https://weibo.com/testuser#tab", "testuser"},
		{"invalid", "https://twitter.com/testuser", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ExtractUsername(tt.url); got != tt.want {
				t.Errorf("ExtractUsername(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsNumeric(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"123456", true},
		{"0", true},
		{"", false},
		{"abc", false},
		{"123abc", false},
		{"12.34", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := isNumeric(tt.input); got != tt.want {
				t.Errorf("isNumeric(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestCleanHometown(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"北京", "北京"},
		{"家乡：北京", "北京"},
		{"家乡:上海", "上海"},
		{"  深圳  ", "深圳"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := cleanHometown(tt.input); got != tt.want {
				t.Errorf("cleanHometown(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
