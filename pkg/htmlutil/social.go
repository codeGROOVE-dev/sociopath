package htmlutil

import (
	"net/url"
	"regexp"
	"strings"
)

// SocialLinks extracts social media URLs from HTML content.
// WARNING: This extracts ALL social media URLs, including links to other people.
// For personal websites, use RelMeLinks instead to get only the page owner's profiles.
func SocialLinks(htmlContent string) []string {
	var urls []string
	seen := make(map[string]bool)

	// Extract URLs matching social media patterns
	for _, pattern := range socialPatterns {
		matches := pattern.FindAllString(htmlContent, -1)
		for _, u := range matches {
			// Clean up trailing non-URL characters (quotes, brackets, etc.)
			u = cleanURL(u)
			// Skip email URLs (like http://email@domain.com) and invalid links
			if u != "" && !seen[u] && !IsEmailURL(u) && isValidProfileLink(u) {
				seen[u] = true
				urls = append(urls, u)
			}
		}
	}

	// Also extract links with social/personal keywords in the link text
	personalLinks := extractPersonalLinks(htmlContent)
	for _, u := range personalLinks {
		// Skip email URLs and duplicates
		if !seen[u] && !IsEmailURL(u) {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	return urls
}

// relMePattern matches anchor tags with rel="me" attribute.
// rel="me" is the standard way to indicate "this link is another profile of mine".
// Matches both <a rel="me" href="..."> and <a href="..." rel="me">.
var relMePattern = regexp.MustCompile(
	`(?i)<a[^>]+rel=["'][^"']*\bme\b[^"']*["'][^>]+href=["']([^"']+)["']` +
		`|<a[^>]+href=["']([^"']+)["'][^>]+rel=["'][^"']*\bme\b[^"']*["']`)

// RelMeLinks extracts only links with rel="me" attribute from HTML content.
// These links indicate the page owner's profiles on other platforms.
// This is the preferred method for personal websites to avoid picking up
// links to collaborators, co-authors, or other people mentioned on the page.
func RelMeLinks(htmlContent string) []string {
	var urls []string
	seen := make(map[string]bool)

	matches := relMePattern.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range matches {
		// One of these will be non-empty depending on attribute order
		href := match[1]
		if href == "" {
			href = match[2]
		}
		href = cleanURL(href)
		if href != "" && !seen[href] && !IsEmailURL(href) {
			seen[href] = true
			urls = append(urls, href)
		}
	}

	return urls
}

// extractPersonalLinks finds URLs with social/personal keywords in link text.
func extractPersonalLinks(htmlContent string) []string {
	var urls []string

	// Pattern to find anchor tags
	anchorPattern := regexp.MustCompile(`(?i)<a[^>]+href=["']?([^\s"'>]+)["']?[^>]*>([^<]*(?:<[^/][^>]*>[^<]*)*)</a>`)
	// Also check markdown-style links: [text](url)
	markdownPattern := regexp.MustCompile(`\[([^\]]+)\]\(([^)]+)\)`)

	// Personal keywords that indicate a personal/social link
	personalKeywords := []string{"blog", "website", "portfolio", "homepage", "personal site"}

	// HTML links
	matches := anchorPattern.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		href := strings.TrimSpace(match[1])
		text := strings.ToLower(strings.TrimSpace(match[2]))

		for _, kw := range personalKeywords {
			if strings.Contains(text, kw) {
				cleanHref := cleanURL(href)
				if cleanHref != "" && strings.HasPrefix(cleanHref, "http") {
					urls = append(urls, cleanHref)
					break
				}
			}
		}
	}

	// Markdown links
	mdMatches := markdownPattern.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range mdMatches {
		if len(match) < 3 {
			continue
		}
		text := strings.ToLower(strings.TrimSpace(match[1]))
		href := strings.TrimSpace(match[2])

		for _, kw := range personalKeywords {
			if strings.Contains(text, kw) {
				cleanHref := cleanURL(href)
				if cleanHref != "" && strings.HasPrefix(cleanHref, "http") {
					urls = append(urls, cleanHref)
					break
				}
			}
		}
	}

	return urls
}

// isValidProfileLink filters out URLs that are system pages, not user profiles.
// Only filters system pages on recognized social platforms - personal websites
// may have /about pages with useful user information.
func isValidProfileLink(urlStr string) bool {
	lower := strings.ToLower(urlStr)

	// Recognized social/platform domains where system pages should be filtered.
	platformDomains := []string{
		// Code hosting
		"github.com", "github.blog", "gitlab.com", "bitbucket.org", "codeberg.org", "gitee.com",
		// Social media
		"twitter.com", "x.com", "facebook.com", "instagram.com",
		"linkedin.com", "youtube.com", "tiktok.com", "twitch.tv",
		"reddit.com", "medium.com", "dev.to", "hashnode.com",
		// Package registries
		"npmjs.com", "pypi.org", "rubygems.org", "crates.io",
		"hub.docker.com", "huggingface.co", "hex.pm",
		// Q&A / Forums
		"stackoverflow.com", "stackexchange.com",
		"hackerone.com", "bugcrowd.com",
		// Identity / Social
		"keybase.io", "gravatar.com",
		"mastodon.social", "hachyderm.io", "fosstodon.org",
		"bsky.app", "vk.com", "weibo.com", "bilibili.com",
		"substack.com", "patreon.com", "ko-fi.com",
		"discord.com", "discordapp.com", "slack.com",
		"telegram.org", "telegram.me", "t.me",
		// Coding challenges
		"leetcode.com", "codewars.com", "hackerrank.com",
		"exercism.org", "freecodecamp.org",
		// Design
		"dribbble.com", "behance.net", "codepen.io",
		// Music / Media
		"soundcloud.com", "spotify.com", "bandcamp.com",
		// Gaming
		"steam.com", "steamcommunity.com",
		// Programming languages and frameworks (their /about pages are site info, not user profiles)
		"scratch.mit.edu", "python.org", "golang.org", "go.dev", "rust-lang.org",
		"ruby-lang.org", "nodejs.org", "deno.land", "typescriptlang.org",
		"kotlinlang.org", "swift.org", "scala-lang.org", "elixir-lang.org",
		"haskell.org", "clojure.org", "erlang.org", "julialang.org",
		"r-project.org", "perl.org", "php.net", "lua.org",
		"reactjs.org", "react.dev", "vuejs.org", "angular.io", "svelte.dev",
		"nextjs.org", "nuxt.com", "astro.build", "remix.run",
		"djangoproject.com", "rubyonrails.org", "flask.palletsprojects.com",
		"spring.io", "laravel.com", "symfony.com",
		"kubernetes.io", "docker.com", "terraform.io", "ansible.com",
		"nginx.org", "apache.org", "linux.org", "kernel.org",
		"mozilla.org", "chromium.org", "webkit.org",
	}

	// Check if URL is on a recognized platform
	isPlatform := false
	for _, domain := range platformDomains {
		if strings.Contains(lower, domain) {
			isPlatform = true
			break
		}
	}

	// Only filter system pages on recognized platforms
	if !isPlatform {
		return true
	}

	// System page paths that are never user profiles
	systemPaths := []string{
		"/about", "/about-us", "/aboutus",
		"/contact", "/contact-us", "/contactus",
		"/help", "/support", "/faq",
		"/terms", "/tos", "/terms-of-service",
		"/privacy", "/privacy-policy",
		"/legal", "/dmca", "/copyright",
		"/press", "/media", "/newsroom",
		"/careers", "/jobs",
		"/blog", "/news",
		"/api", "/developers", "/docs",
		"/security", "/trust",
		"/cookies", "/cookie-policy",
		"/guidelines", "/rules", "/policies",
		"/accessibility",
		"/advertise", "/advertising", "/ads",
		"/partners", "/affiliates",
	}

	for _, sp := range systemPaths {
		if strings.HasSuffix(lower, sp) ||
			strings.Contains(lower, sp+"/") ||
			strings.Contains(lower, sp+"?") {
			return false
		}
	}

	// Platform-specific system page filtering.
	// YouTube has additional paths that don't follow the common pattern.
	if strings.Contains(lower, "youtube.com/") {
		ytSystemPaths := []string{"/creators", "/howyoutubeworks", "/opensearch", "/premium", "/music", "/kids", "/tv"}
		for _, sp := range ytSystemPaths {
			if strings.Contains(lower, sp) {
				return false
			}
		}
	}

	return true
}

// cleanURL removes trailing non-URL characters that might be captured by regex.
func cleanURL(s string) string {
	// Trim whitespace first
	s = strings.TrimSpace(s)

	// Remove trailing quotes, brackets, backslashes, and other HTML/markdown artifacts
	for s != "" {
		last := s[len(s)-1]
		if last != '"' && last != '\'' && last != '>' && last != ')' && last != ']' && last != '\\' {
			break
		}
		s = s[:len(s)-1]
	}

	// Final trim in case artifacts were followed by whitespace
	return strings.TrimSpace(s)
}

var emailPattern = regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)

// knownEmailProviders are domains that are definitely email providers, not web hosts.
// URLs like http://user@gmail.com are clearly misformatted emails, not HTTP basic auth.
var knownEmailProviders = map[string]bool{
	"gmail.com": true, "googlemail.com": true,
	"yahoo.com": true, "yahoo.co.uk": true, "ymail.com": true,
	"hotmail.com": true, "outlook.com": true, "live.com": true, "msn.com": true,
	"icloud.com": true, "me.com": true, "mac.com": true,
	"aol.com": true, "protonmail.com": true, "proton.me": true,
	"fastmail.com": true, "fastmail.fm": true,
	"hey.com": true, "pm.me": true, "mail.com": true, "zoho.com": true,
}

// ExtractEmailFromURL extracts an email address from URLs like "http://user@gmail.com".
// Only recognizes emails at known email providers to avoid confusing HTTP basic auth
// URLs (like https://user@domain.com) with misformatted email addresses.
// Returns the email address and true if found, empty string and false otherwise.
func ExtractEmailFromURL(urlStr string) (string, bool) {
	lower := strings.ToLower(urlStr)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return "", false
	}

	// Remove protocol (case-insensitive)
	withoutProtocol := lower
	withoutProtocol = strings.TrimPrefix(withoutProtocol, "https://")
	withoutProtocol = strings.TrimPrefix(withoutProtocol, "http://")

	// Extract email part (before any path or query)
	if idx := strings.IndexAny(withoutProtocol, "/?#"); idx >= 0 {
		withoutProtocol = withoutProtocol[:idx]
	}

	// Validate it's a proper email pattern
	if !emailPattern.MatchString(withoutProtocol) {
		return "", false
	}

	// Only treat as email if domain is a known email provider.
	// This avoids confusing HTTP basic auth URLs (https://user@domain.com)
	// with misformatted emails (http://user@gmail.com).
	parts := strings.SplitN(withoutProtocol, "@", 2)
	if len(parts) != 2 {
		return "", false
	}
	domain := parts[1]
	if !knownEmailProviders[domain] {
		return "", false
	}

	return withoutProtocol, true
}

// IsEmailURL returns true if the URL is a mailto: link or an email address with http(s):// prefix.
func IsEmailURL(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if strings.HasPrefix(lower, "mailto:") {
		return true
	}
	_, ok := ExtractEmailFromURL(urlStr)
	return ok
}

// commonTLDs contains common valid top-level domains to filter out bogus emails
// extracted from obfuscated text.
var commonTLDs = map[string]bool{
	"com": true, "org": true, "net": true, "edu": true, "gov": true, "mil": true,
	"co": true, "io": true, "me": true, "us": true, "uk": true, "ca": true,
	"de": true, "fr": true, "jp": true, "cn": true, "au": true, "nz": true,
	"in": true, "br": true, "ru": true, "it": true, "es": true, "nl": true,
	"se": true, "no": true, "fi": true, "dk": true, "pl": true, "ch": true,
	"at": true, "be": true, "pt": true, "cz": true, "hu": true, "ro": true,
	"info": true, "biz": true, "dev": true, "app": true, "xyz": true,
	"tech": true, "blog": true, "site": true, "online": true, "cloud": true,
	"ai": true, "cc": true, "tv": true, "fm": true, "sh": true, "ly": true,
	"email": true, "live": true, "mail": true, "gg": true, "pro": true,
	"space": true, "social": true, "link": true, "page": true, "web": true,
}

// isValidEmailDomain checks if the email domain looks valid (not random gibberish).
func isValidEmailDomain(email string) bool {
	atIdx := strings.LastIndex(email, "@")
	if atIdx < 0 {
		return false
	}
	domain := email[atIdx+1:]
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}
	tld := parts[len(parts)-1]

	// Check against common TLDs
	if commonTLDs[tld] {
		return true
	}

	// Reject very short or very long TLDs (most real TLDs are 2-6 chars)
	if len(tld) < 2 || len(tld) > 6 {
		return false
	}

	// Check the domain name (part before TLD) for random-looking strings
	// Real domains usually have pronounceable patterns
	domainName := parts[len(parts)-2]
	if looksLikeRandomString(domainName) || looksLikeRandomString(tld) {
		return false
	}

	return true
}

// looksLikeRandomString checks if a string looks like random gibberish
// by checking for unusual consonant patterns and character distribution.
func looksLikeRandomString(s string) bool {
	if len(s) < 4 {
		return false // Too short to judge
	}

	vowels := 0
	consonants := 0
	consecutiveConsonants := 0
	maxConsecutiveConsonants := 0

	for _, c := range strings.ToLower(s) {
		if c >= 'a' && c <= 'z' {
			if c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' {
				vowels++
				consecutiveConsonants = 0
			} else {
				consonants++
				consecutiveConsonants++
				if consecutiveConsonants > maxConsecutiveConsonants {
					maxConsecutiveConsonants = consecutiveConsonants
				}
			}
		}
	}

	// Random strings often have very high consonant ratios
	if vowels == 0 && consonants > 3 {
		return true
	}

	// More than 4 consecutive consonants is unusual in real words
	if maxConsecutiveConsonants > 4 {
		return true
	}

	// High consonant to vowel ratio (3:1 or more is unusual)
	if vowels > 0 && float64(consonants)/float64(vowels) >= 3.5 {
		return true
	}

	return false
}

// EmailAddresses extracts email addresses from HTML content.
// Filters out common false positives like noreply@, example@, etc.
func EmailAddresses(htmlContent string) []string {
	var emails []string
	seen := make(map[string]bool)

	matches := emailPattern.FindAllString(htmlContent, -1)
	for _, email := range matches {
		email = strings.ToLower(email)

		// Skip common false positives
		if strings.HasPrefix(email, "noreply@") ||
			strings.HasPrefix(email, "no-reply@") ||
			strings.HasPrefix(email, "example@") ||
			strings.Contains(email, "@example.") ||
			strings.Contains(email, "@localhost") ||
			strings.Contains(email, "@test.") ||
			strings.HasSuffix(email, ".png") ||
			strings.HasSuffix(email, ".jpg") ||
			strings.HasSuffix(email, ".gif") {
			continue
		}

		// Skip emails with invalid-looking domains (likely obfuscated text)
		if !isValidEmailDomain(email) {
			continue
		}

		if !seen[email] {
			seen[email] = true
			emails = append(emails, email)
		}
	}

	return emails
}

// PhoneNumbers extracts phone numbers from HTML content.
// Supports various formats: (555) 123-4567, 555-123-4567, +1-555-123-4567, etc.
func PhoneNumbers(htmlContent string) []string {
	var phones []string
	seen := make(map[string]bool)

	matches := phonePattern.FindAllString(htmlContent, -1)
	for _, phone := range matches {
		// Skip numbers that look like they're part of URLs/filenames
		if looksLikeURLFragment(phone) {
			continue
		}

		// Normalize: remove all non-digit characters except leading +
		normalized := normalizePhone(phone)

		// Skip too short (less than 7 digits) or too long numbers
		digitCount := countDigits(normalized)
		if digitCount < 7 || digitCount > 15 {
			continue
		}

		if !seen[normalized] {
			seen[normalized] = true
			phones = append(phones, phone) // Return original format
		}
	}

	return phones
}

// phonePattern matches common phone number formats.
// Requires at least one separator (space, dash, dot, or parentheses) to avoid matching random digit sequences.
var phonePattern = regexp.MustCompile(
	`(?:tel:)?(?:\+?1[-.\s]?)?\([0-9]{3}\)[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}` + // (555) 123-4567
		`|(?:tel:)?(?:\+?1[-.\s]?)?[0-9]{3}[-.\s][0-9]{3}[-.\s]?[0-9]{4}`, // 555-123-4567
)

// looksLikeURLFragment returns true if the string appears to be part of a URL or filename.
func looksLikeURLFragment(s string) bool {
	// Check if it contains characters typical of URLs/filenames
	return strings.Contains(s, "/") ||
		strings.Contains(s, ".js") ||
		strings.Contains(s, ".css") ||
		strings.Contains(s, ".html") ||
		strings.ContainsAny(s, "abcdefABCDEF") // hex chars in hashes
}

func normalizePhone(phone string) string {
	// Remove tel: prefix if present
	phone = strings.TrimPrefix(phone, "tel:")
	// Keep only digits and leading +
	var result strings.Builder
	for i, r := range phone {
		if (r == '+' && i == 0) || (r >= '0' && r <= '9') {
			result.WriteRune(r)
		}
	}
	return result.String()
}

func countDigits(s string) int {
	count := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			count++
		}
	}
	return count
}

// ContactLinks extracts contact/about page URLs from HTML content.
// These pages often contain additional social media links.
func ContactLinks(htmlContent, baseURL string) []string {
	var links []string
	seen := make(map[string]bool)

	// Pattern to find anchor tags with contact-related text
	// Handles both quoted and unquoted href attributes
	anchorPattern := regexp.MustCompile(`(?i)<a[^>]+href=["']?([^\s"'>]+)["']?[^>]*>([^<]*(?:<[^/][^>]*>[^<]*)*)</a>`)
	matches := anchorPattern.FindAllStringSubmatch(htmlContent, -1)

	// Also look for title attributes
	titlePattern := regexp.MustCompile(`(?i)<a[^>]+href=["']?([^\s"'>]+)["']?[^>]*title=["']?([^"'>]+)["']?[^>]*>`)
	titleMatches := titlePattern.FindAllStringSubmatch(htmlContent, -1)
	for _, match := range titleMatches {
		if len(match) >= 3 {
			matches = append(matches, match)
		}
	}

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}
		href := strings.TrimSpace(match[1])
		text := strings.ToLower(strings.TrimSpace(match[2]))
		// Strip HTML tags from text content
		text = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(text, " ")
		text = strings.TrimSpace(text)

		// Look for contact-related link text or title
		contactKeywords := []string{"contact", "about", "about me", "connect", "links", "socials", "find me", "get in touch", "portfolio"}
		isContactLink := false
		for _, kw := range contactKeywords {
			if strings.Contains(text, kw) {
				isContactLink = true
				break
			}
		}

		// Also check href for contact patterns
		hrefLower := strings.ToLower(href)
		if strings.Contains(hrefLower, "/contact") || strings.Contains(hrefLower, "/about") ||
			strings.Contains(hrefLower, "/links") || strings.Contains(hrefLower, "/connect") ||
			strings.Contains(hrefLower, "/portfolio") {
			isContactLink = true
		}

		if !isContactLink {
			continue
		}

		// Resolve relative URLs
		resolved := resolveURL(href, baseURL)
		if resolved == "" {
			continue
		}

		// Skip if same as base URL
		if normalizeForDedup(resolved) == normalizeForDedup(baseURL) {
			continue
		}

		// Skip known social platforms (they'll be picked up separately)
		if isSocialPlatformURL(resolved) {
			continue
		}

		// Skip blog posts (URLs with /posts/, /blog/, /articles/, etc.)
		if isBlogPostURL(resolved) {
			continue
		}

		// Only follow contact/about pages on the same domain to avoid
		// picking up external sites that happen to have "about" in their URL.
		if !isSameDomain(resolved, baseURL) {
			continue
		}

		if !seen[resolved] {
			seen[resolved] = true
			links = append(links, resolved)
		}
	}

	return links
}

// isSameDomain checks if two URLs are on the same domain (ignoring www prefix).
func isSameDomain(url1, url2 string) bool {
	host1 := extractHost(url1)
	host2 := extractHost(url2)
	if host1 == "" || host2 == "" {
		return false
	}
	// Normalize by removing www. prefix
	host1 = strings.TrimPrefix(host1, "www.")
	host2 = strings.TrimPrefix(host2, "www.")
	return host1 == host2
}

// extractHost extracts the hostname from a URL.
func extractHost(urlStr string) string {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}
	return strings.ToLower(parsed.Host)
}

func resolveURL(href, baseURL string) string {
	// Skip javascript, mailto, tel links
	hrefLower := strings.ToLower(href)
	if strings.HasPrefix(hrefLower, "javascript:") || strings.HasPrefix(hrefLower, "mailto:") ||
		strings.HasPrefix(hrefLower, "tel:") || strings.HasPrefix(hrefLower, "#") {
		return ""
	}

	// Already absolute
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		return href
	}

	// Parse base URL
	base, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}

	// Handle protocol-relative URLs
	if strings.HasPrefix(href, "//") {
		return base.Scheme + ":" + href
	}

	// Resolve relative URL
	ref, err := url.Parse(href)
	if err != nil {
		return ""
	}

	return base.ResolveReference(ref).String()
}

func normalizeForDedup(u string) string {
	u = strings.TrimSuffix(u, "/")
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "www.")
	return strings.ToLower(u)
}

func isSocialPlatformURL(u string) bool {
	lower := strings.ToLower(u)
	platforms := []string{
		"twitter.com", "x.com", "linkedin.com", "instagram.com", "facebook.com",
		"youtube.com", "twitch.tv", "tiktok.com", "github.com", "github.blog", "vk.com",
		"habr.com", "habrahabr.ru", "bsky.app", "fosstodon.org", "hachyderm.io",
		"infosec.exchange", "mastodon.social", "mastodon.online",
		"discord.com", "discordapp.com",
		"medium.com", "reddit.com", "substack.com",
		"weibo.com", "weibo.cn", "zhihu.com", "bilibili.com",
		"matrix.to", "matrix.org", "keybase.io",
		"observablehq.com", "opencollective.com", "holopin.io",
		"codepen.io", "freecodecamp.org", "t.me",
		"join.skype.com",
		"cal.com", "calendly.com",
	}
	for _, p := range platforms {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Check for Mastodon pattern (/@username)
	if strings.Contains(lower, "/@") {
		return true
	}
	return false
}

func isBlogPostURL(u string) bool {
	lower := strings.ToLower(u)
	// Common blog post URL patterns
	blogPaths := []string{
		"/posts/", "/post/", "/blog/", "/article/", "/articles/",
		"/news/", "/story/", "/stories/", "/entry/", "/entries/",
	}
	for _, path := range blogPaths {
		if strings.Contains(lower, path) {
			return true
		}
	}
	return false
}

// Pre-compiled patterns for social media URLs.
var socialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`https?://(?:www\.)?twitter\.com/\w+`),
	regexp.MustCompile(`https?://(?:www\.)?x\.com/\w+`),
	regexp.MustCompile(`https?://(?:www\.)?linkedin\.com/in/[\w%-]+/?`), // Allow URL-encoded chars like %C3%B6
	regexp.MustCompile(`https?://(?:www\.)?instagram\.com/[\w.]+`),
	regexp.MustCompile(`https?://(?:www\.)?facebook\.com/[\w.]+`),
	regexp.MustCompile(`https?://(?:www\.)?youtube\.com/(?:@[\w-]+|c/[\w-]+|user/[\w-]+|channel/[\w-]+)`), // YouTube handles and channels
	regexp.MustCompile(`https?://(?:www\.)?twitch\.tv/\w+`),
	regexp.MustCompile(`https?://(?:www\.)?tiktok\.com/@\w+`),
	regexp.MustCompile(`https?://(?:www\.)?github\.com/[\w-]+/?(?:[^\w-/]|$)`),         // Profile only, not /user/project
	regexp.MustCompile(`https?://(?:www\.)?(?:discord|discordapp)\.com/users/[\w.-]+`), // Discord user profiles (numeric ID or username)
	regexp.MustCompile(`https?://(?:www\.)?vk\.com/[\w.]+`),                            // VKontakte
	regexp.MustCompile(`https?://(?:www\.)?habr\.com/(?:ru/)?users/[\w-]+`),            // Habr (formerly Habrhabr)
	regexp.MustCompile(`https?://habrahabr\.ru/users/[\w-]+`),                          // Old Habrhabr domain
	regexp.MustCompile(`https?://(?:www\.)?medium\.com/@[\w-]+`),                       // Medium
	regexp.MustCompile(`https?://(?:www\.)?reddit\.com/user/[\w-]+`),                   // Reddit
	regexp.MustCompile(`https?://(?:old\.)?reddit\.com/user/[\w-]+`),                   // Old Reddit
	regexp.MustCompile(`https?://[\w-]+\.substack\.com`),                               // Substack
	regexp.MustCompile(`https?://(?:www\.)?weibo\.com/[\w-]+`),                         // Weibo
	regexp.MustCompile(`https?://(?:www\.)?weibo\.cn/[\w-]+`),                          // Weibo mobile
	regexp.MustCompile(`https?://(?:www\.)?zhihu\.com/people/[\w-]+`),                  // Zhihu
	regexp.MustCompile(`https?://space\.bilibili\.com/\d+`),                            // Bilibili
	regexp.MustCompile(`https?://(?:www\.)?bilibili\.com/\d+`),                         // Bilibili short URL
	regexp.MustCompile(`skype:[\w.-]+\??[\w=&]*`),                                      // Skype links
	regexp.MustCompile(`https?://bsky\.app/profile/[\w.-]+`),
	regexp.MustCompile(`https?://[\w.-]+\.social/@\w+`),
	regexp.MustCompile(`https?://mastodon\.[\w.-]+/@\w+`),
	regexp.MustCompile(`https?://fosstodon\.org/@\w+`),
	regexp.MustCompile(`https?://hachyderm\.io/@\w+`),
	regexp.MustCompile(`https?://infosec\.exchange/@\w+`),
	// General Mastodon instance pattern - must come after TikTok (which also uses /@user)
	regexp.MustCompile(`https?://[\w.-]+\.\w{2,}/@\w+`),
	// Matrix
	regexp.MustCompile(`https?://matrix\.to/#/@[\w.-]+:[\w.-]+`),
	regexp.MustCompile(`https?://(?:www\.)?matrix\.org/[\w.-]+`),
	// Keybase
	regexp.MustCompile(`https?://(?:www\.)?keybase\.io/[\w.-]+`),
	// Observable
	regexp.MustCompile(`https?://(?:www\.)?observablehq\.com/@[\w-]+`),
	// Open Collective
	regexp.MustCompile(`https?://(?:www\.)?opencollective\.com/[\w-]+`),
	// Holopin
	regexp.MustCompile(`https?://(?:www\.)?holopin\.io/@[\w-]+`),
	// CodePen
	regexp.MustCompile(`https?://(?:www\.)?codepen\.io/[\w-]+`),
	// FreeCodeCamp
	regexp.MustCompile(`https?://(?:www\.)?freecodecamp\.org/[\w-]+`),
	// Telegram
	regexp.MustCompile(`https?://t\.me/[\w-]+`),
	regexp.MustCompile(`https?://(?:www\.)?telegram\.me/[\w-]+`),
	// Scheduling/Calendar
	regexp.MustCompile(`https?://(?:www\.)?cal\.com/[\w-]+(?:/[\w-]+)?`),
	regexp.MustCompile(`https?://(?:www\.)?calendly\.com/[\w-]+(?:/[\w-]+)?`),
}

// Discord username patterns.
var (
	// Old format: username#1234 (discriminator is 4 digits).
	discordOldRe = regexp.MustCompile(`(?i)\b([\w.-]{2,32})#(\d{4})\b`)
	// Contextual patterns for new format usernames.
	discordCtxRe = regexp.MustCompile(`(?i)(?:discord[:\s]+|@?[\w.-]+\s+on\s+discord\s*[:\s]*)(\.?[\w.-]{2,32})`)
)

// ExtractDiscordUsername extracts Discord usernames from text content.
// Returns the username in the format "username#1234" for old format or "username" for new format.
// Returns empty string if no Discord username is found.
// Requires "discord" to be mentioned in the content to avoid false positives.
func ExtractDiscordUsername(s string) string {
	// Require "discord" to be mentioned somewhere to avoid false positives
	if !strings.Contains(strings.ToLower(s), "discord") {
		return ""
	}

	// First try old format with discriminator (more reliable)
	if m := discordOldRe.FindStringSubmatch(s); len(m) > 2 {
		return m[1] + "#" + m[2]
	}

	// Try contextual patterns for new format
	if m := discordCtxRe.FindStringSubmatch(s); len(m) > 1 {
		u := strings.TrimSpace(m[1])
		// Validate it looks like a Discord username (not a sentence fragment)
		if len(u) >= 2 && len(u) <= 32 && !strings.Contains(u, " ") {
			return u
		}
	}

	return ""
}
