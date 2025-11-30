// Package htmlutil provides HTML processing utilities for social media scraping.
package htmlutil

import (
	"html"
	"regexp"
	"strings"
)

// ToMarkdown converts HTML content to markdown format.
func ToMarkdown(htmlContent string) string {
	if htmlContent == "" {
		return ""
	}

	content := htmlContent

	// Remove script and style tags with their content
	content = scriptPattern.ReplaceAllString(content, "")
	content = stylePattern.ReplaceAllString(content, "")

	// Convert headers
	content = h1Pattern.ReplaceAllString(content, "\n# $1\n")
	content = h2Pattern.ReplaceAllString(content, "\n## $1\n")
	content = h3Pattern.ReplaceAllString(content, "\n### $1\n")

	// Convert links
	content = linkPattern.ReplaceAllString(content, "[$2]($1)")

	// Convert paragraphs and line breaks
	content = strings.ReplaceAll(content, "</p>", "\n\n")
	content = strings.ReplaceAll(content, "<p>", "")
	content = strings.ReplaceAll(content, "<br>", "\n")
	content = strings.ReplaceAll(content, "<br/>", "\n")
	content = strings.ReplaceAll(content, "<br />", "\n")

	// Convert lists
	content = strings.ReplaceAll(content, "<li>", "- ")
	content = strings.ReplaceAll(content, "</li>", "\n")
	content = strings.ReplaceAll(content, "<ul>", "\n")
	content = strings.ReplaceAll(content, "</ul>", "\n")
	content = strings.ReplaceAll(content, "<ol>", "\n")
	content = strings.ReplaceAll(content, "</ol>", "\n")

	// Convert bold and italic
	content = boldPattern.ReplaceAllString(content, "**$1**")
	content = italicPattern.ReplaceAllString(content, "*$1*")

	// Remove all remaining HTML tags
	content = tagPattern.ReplaceAllString(content, "")

	// Unescape HTML entities after removing tags
	content = html.UnescapeString(content)

	// Clean up excessive whitespace
	content = multiNewlinePattern.ReplaceAllString(content, "\n\n")
	content = strings.TrimSpace(content)

	return content
}

// Pre-compiled patterns for HTML to Markdown conversion.
var (
	scriptPattern       = regexp.MustCompile(`(?is)<script[^>]*>.*?</script>`)
	stylePattern        = regexp.MustCompile(`(?is)<style[^>]*>.*?</style>`)
	h1Pattern           = regexp.MustCompile(`(?i)<h1[^>]*>(.*?)</h1>`)
	h2Pattern           = regexp.MustCompile(`(?i)<h2[^>]*>(.*?)</h2>`)
	h3Pattern           = regexp.MustCompile(`(?i)<h3[^>]*>(.*?)</h3>`)
	linkPattern         = regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)</a>`)
	boldPattern         = regexp.MustCompile(`(?i)<(?:b|strong)[^>]*>(.*?)</(?:b|strong)>`)
	italicPattern       = regexp.MustCompile(`(?i)<(?:i|em)[^>]*>(.*?)</(?:i|em)>`)
	tagPattern          = regexp.MustCompile(`<[^>]+>`)
	multiNewlinePattern = regexp.MustCompile(`\n{3,}`)
)
