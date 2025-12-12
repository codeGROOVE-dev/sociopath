package htmlutil

import (
	"regexp"
	"strings"
)

// ExtractRedirectURL checks HTML content for meta refresh or JavaScript redirects.
// Returns the redirect URL if found, empty string otherwise.
func ExtractRedirectURL(htmlContent string) string {
	if url := extractMetaRefresh(htmlContent); url != "" {
		return url
	}
	return extractJSRedirect(htmlContent)
}

// extractMetaRefresh finds meta refresh redirect URLs.
// Handles: <meta http-equiv="refresh" content="0;url=https://example.com">
func extractMetaRefresh(content string) string {
	// Pattern matches meta refresh tags with various formats
	// content="0;url=..." or content="0; url=..." or content="0;URL=..."
	pattern := regexp.MustCompile(`(?i)<meta[^>]+http-equiv\s*=\s*["']?refresh["']?[^>]+content\s*=\s*["']?\d+\s*;\s*url\s*=\s*["']?([^"'>\s]+)`)
	if m := pattern.FindStringSubmatch(content); len(m) > 1 {
		return cleanRedirectURL(m[1])
	}

	// Also try reversed attribute order
	pattern2 := regexp.MustCompile(`(?i)<meta[^>]+content\s*=\s*["']?\d+\s*;\s*url\s*=\s*["']?([^"'>\s]+)[^>]+http-equiv\s*=\s*["']?refresh["']?`)
	if m := pattern2.FindStringSubmatch(content); len(m) > 1 {
		return cleanRedirectURL(m[1])
	}

	return ""
}

// extractJSRedirect finds common JavaScript redirect patterns.
// Handles window.location, location.href, document.location assignments and function calls.
func extractJSRedirect(content string) string {
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)window\.location(?:\.href)?\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:^|[^\w.])location(?:\.href)?\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)document\.location(?:\.href)?\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)window\.location\.replace\s*\(\s*["']([^"']+)["']\s*\)`),
		regexp.MustCompile(`(?i)(?:^|[^\w.])location\.replace\s*\(\s*["']([^"']+)["']\s*\)`),
		regexp.MustCompile(`(?i)window\.location\.assign\s*\(\s*["']([^"']+)["']\s*\)`),
	}

	for _, pattern := range patterns {
		if m := pattern.FindStringSubmatch(content); len(m) > 1 {
			url := cleanRedirectURL(m[1])
			// Skip self-referential or fragment-only redirects
			if url != "" && !strings.HasPrefix(url, "#") && url != "." && url != "./" {
				return url
			}
		}
	}

	return ""
}

// cleanRedirectURL cleans up a redirect URL extracted from HTML/JS.
func cleanRedirectURL(url string) string {
	url = strings.TrimSpace(url)
	// Remove trailing quotes or other artifacts
	url = strings.TrimSuffix(url, `"`)
	url = strings.TrimSuffix(url, `'`)
	url = strings.TrimSuffix(url, `>`)
	return url
}
