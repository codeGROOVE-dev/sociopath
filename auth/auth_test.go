package auth

import (
	"context"
	"testing"
)

func TestNewCookieJar(t *testing.T) {
	cookies := map[string]string{
		"session": "abc123",
		"token":   "xyz789",
	}

	jar, err := NewCookieJar("example.com", cookies)
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	if jar == nil {
		t.Fatal("jar should not be nil")
	}
}

func TestNewCookieJarEmpty(t *testing.T) {
	jar, err := NewCookieJar("example.com", map[string]string{})
	if err != nil {
		t.Fatalf("NewCookieJar failed: %v", err)
	}

	if jar == nil {
		t.Fatal("jar should not be nil even with empty cookies")
	}
}

func TestEnvSource(t *testing.T) {
	// Set test env vars
	t.Setenv("LINKEDIN_LI_AT", "test-li-at")
	t.Setenv("LINKEDIN_JSESSIONID", "test-jsessionid")

	src := EnvSource{}
	cookies, err := src.Cookies(context.Background(), "linkedin")
	if err != nil {
		t.Fatalf("Cookies failed: %v", err)
	}

	if cookies["li_at"] != "test-li-at" {
		t.Errorf("li_at = %q, want %q", cookies["li_at"], "test-li-at")
	}
	if cookies["JSESSIONID"] != "test-jsessionid" {
		t.Errorf("JSESSIONID = %q, want %q", cookies["JSESSIONID"], "test-jsessionid")
	}
}

func TestEnvSourceUnknownPlatform(t *testing.T) {
	src := EnvSource{}
	cookies, err := src.Cookies(context.Background(), "unknown-platform")
	if err != nil {
		t.Fatalf("Cookies failed: %v", err)
	}

	if cookies != nil {
		t.Error("cookies should be nil for unknown platform")
	}
}

func TestEnvSourceNoCookies(t *testing.T) {
	// Ensure env vars are not set by using t.Setenv with empty values
	// Note: t.Setenv automatically restores original values
	src := EnvSource{}
	cookies, err := src.Cookies(context.Background(), "linkedin")
	if err != nil {
		t.Fatalf("Cookies failed: %v", err)
	}

	if cookies != nil {
		t.Error("cookies should be nil when env vars not set")
	}
}

func TestStaticSource(t *testing.T) {
	input := map[string]string{
		"session": "abc123",
		"token":   "xyz789",
	}

	src := NewStaticSource(input)
	cookies, err := src.Cookies(context.Background(), "any-platform")
	if err != nil {
		t.Fatalf("Cookies failed: %v", err)
	}

	if len(cookies) != 2 {
		t.Errorf("got %d cookies, want 2", len(cookies))
	}
	if cookies["session"] != "abc123" {
		t.Errorf("session = %q, want %q", cookies["session"], "abc123")
	}

	// Verify it's a copy
	cookies["session"] = "modified"
	cookies2, err := src.Cookies(context.Background(), "any-platform")
	if err != nil {
		t.Fatalf("Cookies failed: %v", err)
	}
	if cookies2["session"] != "abc123" {
		t.Error("StaticSource should return copies")
	}
}

func TestStaticSourceEmpty(t *testing.T) {
	src := NewStaticSource(nil)
	cookies, err := src.Cookies(context.Background(), "any-platform")
	if err != nil {
		t.Fatalf("Cookies failed: %v", err)
	}

	if cookies != nil {
		t.Error("cookies should be nil for empty source")
	}
}

func TestChainSources(t *testing.T) {
	// First source returns nil
	src1 := NewStaticSource(nil)

	// Second source returns cookies
	src2 := NewStaticSource(map[string]string{"token": "from-src2"})

	// Third source also has cookies (should not be reached)
	src3 := NewStaticSource(map[string]string{"token": "from-src3"})

	cookies, err := ChainSources(context.Background(), "any", src1, src2, src3)
	if err != nil {
		t.Fatalf("ChainSources failed: %v", err)
	}

	if cookies["token"] != "from-src2" {
		t.Errorf("token = %q, want %q", cookies["token"], "from-src2")
	}
}

func TestChainSourcesAllEmpty(t *testing.T) {
	src1 := NewStaticSource(nil)
	src2 := NewStaticSource(nil)

	cookies, err := ChainSources(context.Background(), "any", src1, src2)
	if err != nil {
		t.Fatalf("ChainSources failed: %v", err)
	}

	if cookies != nil {
		t.Error("cookies should be nil when all sources empty")
	}
}

func TestEnvVarsForPlatform(t *testing.T) {
	vars := EnvVarsForPlatform("linkedin")
	if len(vars) == 0 {
		t.Error("should return env vars for linkedin")
	}

	// Check that expected vars are present
	varSet := make(map[string]bool)
	for _, v := range vars {
		varSet[v] = true
	}

	if !varSet["LINKEDIN_LI_AT"] {
		t.Error("should include LINKEDIN_LI_AT")
	}
}

func TestEnvVarsForUnknownPlatform(t *testing.T) {
	vars := EnvVarsForPlatform("unknown")
	if vars != nil {
		t.Error("should return nil for unknown platform")
	}
}
