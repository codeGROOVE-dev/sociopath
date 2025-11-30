package auth

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/browserutils/kooky"
	_ "github.com/browserutils/kooky/browser/all" // Import all browser cookie stores
	"github.com/browserutils/kooky/browser/firefox"
)

// platformDomains maps platform names to their cookie domains.
var platformDomains = map[string]string{
	"linkedin": "linkedin.com",
	"twitter":  "x.com",
	"tiktok":   "tiktok.com",
}

// platformEssentialCookies maps platform names to their required cookie names.
var platformEssentialCookies = map[string][]string{
	"linkedin": {"li_at", "JSESSIONID", "lidc", "bcookie"},
	"twitter":  {"auth_token", "ct0", "kdt", "twid", "att"},
	"tiktok":   {"sessionid"},
}

// BrowserSource reads cookies from browser cookie stores.
type BrowserSource struct {
	logger *slog.Logger
}

// NewBrowserSource creates a new browser cookie source.
func NewBrowserSource(logger *slog.Logger) *BrowserSource {
	if logger == nil {
		logger = slog.Default()
	}
	return &BrowserSource{logger: logger}
}

// Cookies returns cookies for the given platform from browser stores.
func (s *BrowserSource) Cookies(ctx context.Context, platform string) (map[string]string, error) {
	domain, ok := platformDomains[platform]
	if !ok {
		return nil, nil //nolint:nilnil // no cookies for unknown platform is not an error
	}

	// Try Firefox profiles first (including Developer Edition)
	cookies := s.tryFirefoxProfiles(ctx, domain, platform)
	if len(cookies) > 0 {
		return cookies, nil
	}

	// Fall back to kooky's automatic browser detection
	kookies, err := kooky.ReadCookies(ctx, kooky.Valid, kooky.DomainHasSuffix(domain))
	if err != nil {
		s.logger.Debug("failed to read browser cookies", "platform", platform, "error", err)
		return nil, nil //nolint:nilnil // failed browser read is not a fatal error
	}

	if len(kookies) == 0 {
		return nil, nil //nolint:nilnil // no browser cookies is not an error
	}

	return s.filterEssentialCookies(kookies, platform), nil
}

// tryFirefoxProfiles attempts to read cookies from Firefox profiles.
func (s *BrowserSource) tryFirefoxProfiles(ctx context.Context, domain, platform string) map[string]string {
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}

	dir := filepath.Join(home, "Library", "Application Support", "Firefox", "Profiles")
	pattern := filepath.Join(dir, "*", "cookies.sqlite")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}

	for _, f := range matches {
		kookies, err := firefox.ReadCookies(ctx, f, kooky.Valid, kooky.DomainHasSuffix(domain))
		if err == nil && len(kookies) > 0 {
			s.logger.Debug("found Firefox cookies",
				"profile", filepath.Base(filepath.Dir(f)),
				"platform", platform,
				"count", len(kookies))
			return s.filterEssentialCookies(kookies, platform)
		}
	}

	return nil
}

// filterEssentialCookies extracts only the required cookies for a platform.
func (s *BrowserSource) filterEssentialCookies(kookies []*kooky.Cookie, platform string) map[string]string {
	essential, ok := platformEssentialCookies[platform]
	if !ok {
		// No filter defined, return all cookies
		cookies := make(map[string]string)
		for _, c := range kookies {
			cookies[c.Name] = c.Value
		}
		return cookies
	}

	essentialSet := make(map[string]bool)
	for _, name := range essential {
		essentialSet[name] = true
	}

	cookies := make(map[string]string)
	for _, c := range kookies {
		if essentialSet[c.Name] {
			cookies[c.Name] = c.Value
			s.logger.Debug("found essential cookie", "name", c.Name, "len", len(c.Value))
		}
	}

	return cookies
}
