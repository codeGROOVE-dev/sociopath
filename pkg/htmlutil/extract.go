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

// OGTag extracts an Open Graph meta tag value by property name.
// Handles both property="og:xxx" content="value" and content="value" property="og:xxx" orders.
func OGTag(htmlContent, property string) string {
	// Try property before content
	pattern1 := regexp.MustCompile(`(?i)<meta[^>]+property=["']` + regexp.QuoteMeta(property) + `["'][^>]+content=["']([^"']+)["']`)
	if matches := pattern1.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	// Try content before property
	pattern2 := regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+property=["']` + regexp.QuoteMeta(property) + `["']`)
	if matches := pattern2.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	return ""
}

// OGImage extracts an image URL from HTML meta tags.
// Priority: og:image > twitter:image > banner/hero image in srcset.
func OGImage(htmlContent string) string {
	// Try og:image first (most common)
	if matches := ogImagePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	// Try reverse order (content before property)
	if matches := ogImagePatternAlt.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	// Try twitter:image
	if matches := twitterImagePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	if matches := twitterImagePatternAlt.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	// Fallback: look for banner/hero images in preload or srcset
	if matches := bannerImagePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
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

	// Image extraction patterns.
	ogImagePattern         = regexp.MustCompile(`(?i)<meta[^>]+property=["']og:image["'][^>]+content=["']([^"']+)["']`)
	ogImagePatternAlt      = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+property=["']og:image["']`)
	twitterImagePattern    = regexp.MustCompile(`(?i)<meta[^>]+name=["']twitter:image["'][^>]+content=["']([^"']+)["']`)
	twitterImagePatternAlt = regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']twitter:image["']`)
	bannerImagePattern     = regexp.MustCompile(`(?i)(?:srcset|src)=["']([^"']*(?:banner|hero)[^"']*)["']`)
)
