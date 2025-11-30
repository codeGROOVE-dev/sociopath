package htmlutil

import (
	"html"
	"regexp"
	"strings"
)

// Title extracts the title from HTML content.
func Title(htmlContent string) string {
	// Try <title> tag
	if matches := titlePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}

	// Try og:title meta tag
	if matches := ogTitlePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}

	// Try h1 tag
	if matches := firstH1Pattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}

	return ""
}

// Description extracts the meta description from HTML content.
func Description(htmlContent string) string {
	// Try meta description
	if matches := descPattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}

	// Try og:description
	if matches := ogDescPattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}

	return ""
}

// Pre-compiled patterns for extraction.
var (
	titlePattern   = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	ogTitlePattern = regexp.MustCompile(`(?i)<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']`)
	firstH1Pattern = regexp.MustCompile(`(?i)<h1[^>]*>([^<]+)</h1>`)
	descPattern    = regexp.MustCompile(`(?i)<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']`)
	ogDescPattern  = regexp.MustCompile(`(?i)<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']`)
)
