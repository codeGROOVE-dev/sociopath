package auth

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/browserutils/kooky"
	_ "github.com/browserutils/kooky/browser/all" // Import all browser cookie stores
	"github.com/browserutils/kooky/browser/chrome"
	"github.com/browserutils/kooky/browser/firefox"
)

// platformDomains maps platform names to their cookie domains.
var platformDomains = map[string]string{
	"instagram": "instagram.com",
	"linkedin":  "linkedin.com",
	"tiktok":    "tiktok.com",
	"twitter":   "x.com",
	"vkontakte": "vk.com",
	"weibo":     "weibo.com",
	"google":    "google.com",
}

// platformEssentialCookies maps platform names to their required cookie names.
var platformEssentialCookies = map[string][]string{
	"instagram": {"sessionid", "csrftoken"},
	"linkedin":  {"li_at", "JSESSIONID", "lidc", "bcookie"},
	"tiktok":    {"sessionid"},
	"twitter":   {"auth_token", "ct0", "kdt", "twid", "att"},
	"vkontakte": {"remixsid"},
	"weibo":     {"SUB", "SUBP"},
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

	s.logger.DebugContext(ctx, "reading browser cookies", "platform", platform, "domain", domain)

	// Try Zen Browser first (Firefox-based, not auto-detected by kooky)
	cookies := s.tryZenBrowser(ctx, domain, platform)
	if len(cookies) > 0 {
		return cookies, nil
	}

	// Try Chrome Canary (not auto-detected by kooky)
	cookies = s.tryChromeCanary(ctx, domain, platform)
	if len(cookies) > 0 {
		return cookies, nil
	}

	// Try Firefox profiles (including Developer Edition)
	cookies = s.tryFirefoxProfiles(ctx, domain, platform)
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

// tryZenBrowser attempts to read cookies from Zen Browser profiles (Firefox-based).
func (s *BrowserSource) tryZenBrowser(ctx context.Context, domain, platform string) map[string]string {
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}

	zenDir := filepath.Join(home, "Library", "Application Support", "zen", "Profiles")
	pattern := filepath.Join(zenDir, "*", "cookies.sqlite")
	matches, err := filepath.Glob(pattern)
	if err != nil || len(matches) == 0 {
		return nil
	}

	for _, f := range matches {
		kookies, err := firefox.ReadCookies(ctx, f, kooky.Valid, kooky.DomainHasSuffix(domain))
		if err != nil {
			s.logger.Debug("failed to read Zen Browser cookies",
				"profile", filepath.Base(filepath.Dir(f)),
				"platform", platform,
				"error", err)
			continue
		}
		if len(kookies) > 0 {
			s.logger.Debug("found Zen Browser cookies",
				"profile", filepath.Base(filepath.Dir(f)),
				"platform", platform,
				"count", len(kookies))
			return s.filterEssentialCookies(kookies, platform)
		}
	}

	return nil
}

// tryChromeCanary attempts to read cookies from Chrome Canary profiles.
func (s *BrowserSource) tryChromeCanary(ctx context.Context, domain, platform string) map[string]string {
	home := os.Getenv("HOME")
	if home == "" {
		return nil
	}

	canaryDir := filepath.Join(home, "Library", "Application Support", "Google", "Chrome Canary")
	profiles := []string{"Default", "Profile 1", "Profile 2", "Profile 3", "Profile 4", "Profile 5"}

	for _, profile := range profiles {
		cookiesFile := filepath.Join(canaryDir, profile, "Cookies")
		if _, err := os.Stat(cookiesFile); err != nil {
			continue
		}

		kookies, err := chrome.ReadCookies(ctx, cookiesFile, kooky.Valid, kooky.DomainHasSuffix(domain))
		if err != nil {
			// Check for encryption errors and warn user
			if strings.Contains(err.Error(), "encryption") || strings.Contains(err.Error(), "decrypt") {
				s.logger.Warn("Chrome Canary cookies exist but cannot be decrypted",
					"profile", profile,
					"platform", platform,
					"hint", "try using Firefox, Zen Browser, or set cookies via environment variables")
			} else {
				s.logger.Debug("failed to read Chrome Canary cookies", "profile", profile, "platform", platform, "error", err)
			}
			continue
		}

		if len(kookies) > 0 {
			s.logger.Debug("found Chrome Canary cookies", "profile", profile, "platform", platform, "count", len(kookies))
			return s.filterEssentialCookies(kookies, platform)
		}
	}

	return nil
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
		}
	}

	// Log which essential cookies were found vs missing
	var found, missing []string
	for _, name := range essential {
		if _, ok := cookies[name]; ok {
			found = append(found, name)
		} else {
			missing = append(missing, name)
		}
	}

	if len(found) > 0 {
		s.logger.Info("browser cookies found", "platform", platform, "keys", found)
	}
	if len(missing) > 0 {
		s.logger.Info("browser cookies missing", "platform", platform, "keys", missing)
	}

	return cookies
}
