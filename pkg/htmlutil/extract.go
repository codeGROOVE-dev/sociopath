// Package htmlutil provides HTML processing utilities for social media scraping.
package htmlutil

import (
	"html"
	"regexp"
	"strings"
)

// StripTags removes HTML tags and returns plain text.
func StripTags(htmlContent string) string {
	if htmlContent == "" {
		return ""
	}
	content := tagPattern.ReplaceAllString(htmlContent, " ")
	content = html.UnescapeString(content)
	content = multiSpacePattern.ReplaceAllString(content, " ")
	return strings.TrimSpace(content)
}

// Title extracts the title from HTML content.
func Title(htmlContent string) string {
	if matches := titlePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	if matches := ogTitlePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	if matches := firstH1Pattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	return ""
}

// Description extracts the meta description from HTML content.
func Description(htmlContent string) string {
	if matches := descPattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	if matches := ogDescPattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	return ""
}

var (
	tagPattern        = regexp.MustCompile(`<[^>]+>`)
	multiSpacePattern = regexp.MustCompile(`\s+`)
	titlePattern      = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)
	ogTitlePattern    = regexp.MustCompile(`(?i)<meta[^>]+property=["']og:title["'][^>]+content=["']([^"']+)["']`)
	firstH1Pattern    = regexp.MustCompile(`(?i)<h1[^>]*>([^<]+)</h1>`)
	descPattern       = regexp.MustCompile(`(?i)<meta[^>]+name=["']description["'][^>]+content=["']([^"']+)["']`)
	ogDescPattern     = regexp.MustCompile(`(?i)<meta[^>]+property=["']og:description["'][^>]+content=["']([^"']+)["']`)
)
