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

// IsNotFound detects common "404 Not Found" or "Page not found" patterns in HTML content.
func IsNotFound(text string) bool {
	lower := strings.ToLower(text)
	patterns := []string{
		"404 not found",
		"page not found",
		"error 404",
		"the page you requested cannot be found",
		"user not found",
		"profile not found",
		"designer not found",
		"agency not found",
		"this account has been suspended",
		"account not found",
		"could not find this user",
		"user does not exist",
		"no user found",
		"no such user",
		"invalid user",
		"requested user was not found",
		"the user you are looking for does not exist",
		"this page doesn't exist",
		"couldn't find that page",
		"no user was found",
		"user not found",
		"member not found",
		"this profile is not available",
		"why are you here?",
		"you've gotta love crab.",
	}
	for _, p := range patterns {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// IsGenericTitle returns true if the title looks like a generic site title
// rather than a specific user profile title.
func IsGenericTitle(title string) bool {
	lower := strings.ToLower(title)
	genericTitles := []string{
		"coding games and programming challenges to code better",
		"hack this site",
		"codesandbox",
		"behance",
		"daily.dev",
		"daily.dev | where developers grow together",
		"mastodon",
		"hahow",
		"error 404",
		"404 not found",
		"page not found",
	}
	for _, gt := range genericTitles {
		if strings.EqualFold(lower, gt) {
			return true
		}
	}
	return false
}

// IsGenericBio returns true if the bio looks like a generic site description
// rather than a specific user bio.
func IsGenericBio(bio string) bool {
	lower := strings.ToLower(bio)
	genericBios := []string{
		"daily.dev is the easiest way to stay updated on the latest programming news.",
		"the cost of living is dying.",
		"sign up to follow",
	}
	for _, gb := range genericBios {
		if strings.Contains(lower, gb) {
			return true
		}
	}
	return false
}

// StripHTML is an alias for StripTags for backward compatibility.
func StripHTML(htmlContent string) string {
	return StripTags(htmlContent)
}

// DecodeHTMLEntities decodes HTML entities in a string.
func DecodeHTMLEntities(s string) string {
	return html.UnescapeString(s)
}

// OGTitle extracts the og:title from HTML content.
func OGTitle(htmlContent string) string {
	if matches := ogTitlePattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(html.UnescapeString(matches[1]))
	}
	return ""
}

// ExtractJSONLD extracts JSON-LD structured data from HTML as a JSON string.
func ExtractJSONLD(htmlContent string) string {
	// Find JSON-LD script tags
	pattern := regexp.MustCompile(`(?s)<script[^>]*type=["']application/ld\+json["'][^>]*>(.*?)</script>`)
	if matches := pattern.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// ExtractMetaTag extracts a meta tag value by name or property.
func ExtractMetaTag(htmlContent, nameOrProperty string) string {
	// Try name attribute first
	pattern1 := regexp.MustCompile(`(?i)<meta[^>]+name=["']` + regexp.QuoteMeta(nameOrProperty) + `["'][^>]+content=["']([^"']+)["']`)
	if matches := pattern1.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return html.UnescapeString(strings.TrimSpace(matches[1]))
	}
	// Try content before name
	pattern2 := regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+name=["']` + regexp.QuoteMeta(nameOrProperty) + `["']`)
	if matches := pattern2.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return html.UnescapeString(strings.TrimSpace(matches[1]))
	}
	// Try property attribute
	pattern3 := regexp.MustCompile(`(?i)<meta[^>]+property=["']` + regexp.QuoteMeta(nameOrProperty) + `["'][^>]+content=["']([^"']+)["']`)
	if matches := pattern3.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return html.UnescapeString(strings.TrimSpace(matches[1]))
	}
	// Try content before property
	pattern4 := regexp.MustCompile(`(?i)<meta[^>]+content=["']([^"']+)["'][^>]+property=["']` + regexp.QuoteMeta(nameOrProperty) + `["']`)
	if matches := pattern4.FindStringSubmatch(htmlContent); len(matches) > 1 {
		return html.UnescapeString(strings.TrimSpace(matches[1]))
	}
	return ""
}
