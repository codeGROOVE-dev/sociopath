// Package generic provides HTML fallback extraction for unknown social media platforms.
package generic

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/discovery"
	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const (
	platform     = "website"
	maxBlogPosts = 50
)

// Match always returns true as this is the fallback.
func Match(_ string) bool { return true }

// AuthRequired returns false.
func AuthRequired() bool { return false }

// Client handles generic website requests.
type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a generic client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves content from a generic website and converts to markdown.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	// Normalize URL
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	// Security: validate URL
	if err := validateURL(urlStr); err != nil {
		return nil, err
	}

	c.logger.InfoContext(ctx, "fetching generic website", "url", urlStr)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	// Detect bot protection pages that look like valid responses
	if isBotProtectionPage(body) {
		return nil, errors.New("bot protection page detected")
	}

	p := parseHTML(body, urlStr)

	// Run identity discovery for the domain
	disc := discovery.New(c.cache, c.logger)
	domain := discovery.ExtractDomain(urlStr)
	for _, result := range disc.DiscoverAll(ctx, domain) {
		p.SocialLinks = append(p.SocialLinks, result.URL)
		c.logger.InfoContext(ctx, "discovered identity", "platform", result.Platform, "domain", domain, "url", result.URL)
	}

	// Check WebFinger for emails with custom domains (Fediverse/Mastodon discovery)
	if email := p.Fields["email"]; email != "" {
		if result := disc.LookupWebFinger(ctx, email); result != nil {
			p.SocialLinks = append(p.SocialLinks, result.URL)
			c.logger.InfoContext(ctx, "discovered fediverse via WebFinger", "email", email, "url", result.URL)
		}
	}

	return p, nil
}

func parseHTML(data []byte, urlStr string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Fields:        make(map[string]string),
	}

	p.PageTitle = htmlutil.Title(content)
	p.Bio = htmlutil.Description(content)
	p.AvatarURL = htmlutil.OGImage(content)
	p.Content = content

	// Extract only rel="me" links from personal websites.
	// This avoids picking up links to collaborators/co-authors mentioned on the page.
	// rel="me" is the standard way to indicate "this is another profile of mine".
	p.SocialLinks = htmlutil.RelMeLinks(content)

	// For contact/about pages, also extract all social media links since these
	// pages are typically about a single person, not collaborators.
	if isContactPage(urlStr) {
		p.SocialLinks = append(p.SocialLinks, htmlutil.SocialLinks(content)...)
	}

	// Also extract contact/about page links for recursion
	contactLinks := htmlutil.ContactLinks(content, urlStr)
	p.SocialLinks = append(p.SocialLinks, contactLinks...)

	// Deduplicate social links
	p.SocialLinks = dedupeLinks(p.SocialLinks)

	// Extract emails
	emails := htmlutil.EmailAddresses(content)
	if len(emails) > 0 {
		p.Fields["email"] = cleanEmail(emails[0]) // Primary email
		if len(emails) > 1 {
			// Store additional emails
			for i, email := range emails[1:] {
				p.Fields[fmt.Sprintf("email_%d", i+2)] = cleanEmail(email)
			}
		}
	}

	// Extract phone numbers
	phones := htmlutil.PhoneNumbers(content)
	if len(phones) > 0 {
		p.Fields["phone"] = phones[0]
	}

	// Extract blog posts if this looks like a blog
	if posts, lastActive := extractBlogPosts(content, urlStr); len(posts) > 0 {
		p.Posts = posts
		p.Platform = "blog"
		if lastActive != "" {
			p.UpdatedAt = lastActive
		} else if len(posts) > 0 && posts[0].URL != "" {
			p.UpdatedAt = extractDateFromURL(posts[0].URL)
		}
	}

	return p
}

// isContactPage returns true if the URL is likely a contact or about page,
// or a homepage of a personal domain (where all social links belong to the owner).
func isContactPage(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if strings.Contains(lower, "/contact") ||
		strings.Contains(lower, "/about") ||
		strings.Contains(lower, "/links") ||
		strings.Contains(lower, "/connect") ||
		strings.Contains(lower, "/socials") {
		return true
	}

	// Root pages of personal domains are effectively "about" pages
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return false
	}
	path := strings.TrimSuffix(parsed.Path, "/")
	return path == ""
}

// blogPost represents a blog post with optional date for sorting.
type blogPost struct {
	post profile.Post
	date string // YYYY-MM-DD format for sorting
}

// extractBlogPosts detects if a page is a blog and extracts post entries.
// Returns posts and the date of the most recent post (if available).
func extractBlogPosts(content, baseURL string) (posts []profile.Post, lastActive string) {
	// Check for blog indicators
	if !isBlogPage(content) {
		return nil, ""
	}

	var bposts []blogPost

	// Parse base URL for resolving relative links
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, ""
	}

	// Pattern 1: Links with dates in format YYYY-MM-DD or similar near them
	// e.g., <a href="/posts/2025/...">Title</a> - 2025-07-07
	datePostPattern := regexp.MustCompile(`(?i)<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)</a>\s*[-–—]\s*(\d{4}-\d{2}-\d{2})`)
	for _, m := range datePostPattern.FindAllStringSubmatch(content, maxBlogPosts) {
		postURL := resolveURL(base, m[1])
		if !isPostURL(postURL) {
			continue
		}
		bposts = append(bposts, blogPost{
			post: profile.Post{
				Type:  profile.PostTypeArticle,
				Title: html.UnescapeString(strings.TrimSpace(m[2])),
				URL:   postURL,
			},
			date: m[3],
		})
	}

	// If we found posts with the date pattern, return them
	if len(bposts) > 0 {
		return toBlogPosts(bposts)
	}

	// Pattern 2: Links with date prefix in link text (e.g., "2023-04-25 – Title")
	datePrefixPattern := regexp.MustCompile(`<a[^>]+href=["']([^"']+)["'][^>]*>(\d{4}-\d{2}-\d{2})\s*[-–—]\s*([^<]+)</a>`)
	for _, m := range datePrefixPattern.FindAllStringSubmatch(content, maxBlogPosts) {
		postURL := resolveURL(base, m[1])
		if !isPostURL(postURL) {
			continue
		}
		bposts = append(bposts, blogPost{
			post: profile.Post{
				Type:  profile.PostTypeArticle,
				Title: html.UnescapeString(strings.TrimSpace(m[3])),
				URL:   postURL,
			},
			date: m[2],
		})
	}

	if len(bposts) > 0 {
		return toBlogPosts(bposts)
	}

	// Pattern 3: Jekyll-style post list with date span before link
	// e.g., <li><span>19 Feb 2015</span> &raquo; <a href="URL">Title</a></li>
	jekyllRe := `<li>\s*<span>(\d{1,2})\s+(\w{3})\s+(\d{4})</span>\s*(?:&raquo;|»)\s*` +
		`<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)</a>`
	jekyllPattern := regexp.MustCompile(jekyllRe)
	for _, m := range jekyllPattern.FindAllStringSubmatch(content, maxBlogPosts) {
		postURL := resolveURL(base, m[4])
		if !isPostURL(postURL) {
			continue
		}
		date := parseHumanDate(m[1], m[2], m[3])
		bposts = append(bposts, blogPost{
			post: profile.Post{
				Type:  profile.PostTypeArticle,
				Title: html.UnescapeString(strings.TrimSpace(m[5])),
				URL:   postURL,
			},
			date: date,
		})
	}

	if len(bposts) > 0 {
		return toBlogPosts(bposts)
	}

	// Pattern 4: Links followed by date in MM.DD.YYYY or MM.DD.YY format
	// e.g., <a href="URL">Title</a> ... : 05.15.2020
	usDatePattern := regexp.MustCompile(`<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)</a>[^<]*:\s*(\d{1,2})\.(\d{1,2})\.(\d{2,4})`)
	for _, m := range usDatePattern.FindAllStringSubmatch(content, maxBlogPosts) {
		postURL := resolveURL(base, m[1])
		title := html.UnescapeString(strings.TrimSpace(m[2]))
		// Skip navigation links
		if isNavLink(title) {
			continue
		}
		month := m[3]
		day := m[4]
		year := m[5]
		if len(year) == 2 {
			year = "20" + year
		}
		date := fmt.Sprintf("%s-%02s-%02s", year, month, day)
		bposts = append(bposts, blogPost{
			post: profile.Post{
				Type:  profile.PostTypeArticle,
				Title: title,
				URL:   postURL,
			},
			date: date,
		})
	}

	if len(bposts) > 0 {
		return toBlogPosts(bposts)
	}

	// Pattern 5: All links within an <article> element pointing to post URLs
	articlePattern := regexp.MustCompile(`(?is)<article[^>]*>(.*?)</article>`)
	if m := articlePattern.FindStringSubmatch(content); len(m) > 1 {
		articleContent := m[1]
		linkPattern := regexp.MustCompile(`<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)</a>`)
		for _, lm := range linkPattern.FindAllStringSubmatch(articleContent, maxBlogPosts) {
			postURL := resolveURL(base, lm[1])
			if !isPostURL(postURL) {
				continue
			}
			bposts = append(bposts, blogPost{
				post: profile.Post{
					Type:  profile.PostTypeArticle,
					Title: html.UnescapeString(strings.TrimSpace(lm[2])),
					URL:   postURL,
				},
				date: extractDateFromURL(postURL),
			})
		}
	}

	if len(bposts) > 0 {
		return toBlogPosts(bposts)
	}

	// Pattern 6: Look for links in post/blog sections
	// Find section with "posts", "articles", "blog" heading, then extract links
	sectionPattern := regexp.MustCompile(`(?is)<h[123][^>]*>[^<]*(?:posts?|articles?|blog)[^<]*</h[123]>\s*(.*?)(?:<h[123]|</body|$)`)
	if m := sectionPattern.FindStringSubmatch(content); len(m) > 1 {
		sectionContent := m[1]
		linkPattern := regexp.MustCompile(`<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)</a>`)
		for _, lm := range linkPattern.FindAllStringSubmatch(sectionContent, maxBlogPosts) {
			postURL := resolveURL(base, lm[1])
			if !isPostURL(postURL) {
				continue
			}
			bposts = append(bposts, blogPost{
				post: profile.Post{
					Type:  profile.PostTypeArticle,
					Title: html.UnescapeString(strings.TrimSpace(lm[2])),
					URL:   postURL,
				},
				date: extractDateFromURL(postURL),
			})
		}
	}

	if len(bposts) > 0 {
		return toBlogPosts(bposts)
	}

	// Pattern 7: Links containing headings followed by time elements (Hugo/Micro.blog style)
	// e.g., <a href="URL"><h1>Title</h1></a> ... <time datetime="...">DATE</time>
	headingLinkRe := `(?is)<a[^>]+href=["']([^"']+)["'][^>]*>\s*<h[1-6][^>]*>([^<]+)</h[1-6]>\s*</a>` +
		`.*?<time[^>]*(?:datetime=["']([^"']+)["'])?[^>]*>\s*(\d{4}-\d{2}-\d{2})`
	headingLinkPattern := regexp.MustCompile(headingLinkRe)
	for _, m := range headingLinkPattern.FindAllStringSubmatch(content, maxBlogPosts) {
		postURL := resolveURL(base, m[1])
		title := html.UnescapeString(strings.TrimSpace(m[2]))
		date := m[4] // The visible date
		bposts = append(bposts, blogPost{
			post: profile.Post{
				Type:  profile.PostTypeArticle,
				Title: title,
				URL:   postURL,
			},
			date: date,
		})
	}

	return toBlogPosts(bposts)
}

// toBlogPosts converts blogPost slice to profile.Post slice, limiting to maxBlogPosts.
// Returns posts and the most recent date (if any).
func toBlogPosts(bposts []blogPost) (posts []profile.Post, lastActive string) {
	if len(bposts) > maxBlogPosts {
		bposts = bposts[:maxBlogPosts]
	}
	posts = make([]profile.Post, len(bposts))
	for i, bp := range bposts {
		posts[i] = bp.post
		// First post with a date is the most recent
		if lastActive == "" && bp.date != "" {
			lastActive = bp.date
		}
	}
	return posts, lastActive
}

// parseHumanDate converts day, month name, year to YYYY-MM-DD format.
func parseHumanDate(day, month, year string) string {
	months := map[string]string{
		"jan": "01", "feb": "02", "mar": "03", "apr": "04",
		"may": "05", "jun": "06", "jul": "07", "aug": "08",
		"sep": "09", "oct": "10", "nov": "11", "dec": "12",
	}
	m := months[strings.ToLower(month)]
	if m == "" {
		return ""
	}
	d := day
	if len(d) == 1 {
		d = "0" + d
	}
	return fmt.Sprintf("%s-%s-%s", year, m, d)
}

// isNavLink returns true if the title looks like a navigation link.
func isNavLink(title string) bool {
	lower := strings.ToLower(title)
	navWords := []string{"home", "about", "contact", "rss", "feed", "github", "twitter", "profile"}
	for _, word := range navWords {
		if lower == word || strings.HasPrefix(lower, word+" ") {
			return true
		}
	}
	return false
}

// isBlogPage checks if the page appears to be a blog.
func isBlogPage(content string) bool {
	lower := strings.ToLower(content)

	// Check for RSS/Atom feed links (strong signal)
	if strings.Contains(lower, "application/rss+xml") || strings.Contains(lower, "application/atom+xml") {
		return true
	}

	// Check for blog-related URL patterns in links
	blogURLPatterns := []string{"/posts/", "/post/", "/blog/", "/articles/", "/article/"}
	linkCount := 0
	for _, pattern := range blogURLPatterns {
		linkCount += strings.Count(lower, pattern)
	}
	if linkCount >= 3 {
		return true
	}

	// Check for blog-related headings
	headingPattern := regexp.MustCompile(`(?i)<h[123][^>]*>[^<]*(?:recent posts?|latest posts?|blog posts?|articles?)[^<]*</h[123]>`)
	return headingPattern.MatchString(content)
}

// isPostURL checks if a URL looks like a blog post URL.
func isPostURL(urlStr string) bool {
	lower := strings.ToLower(urlStr)

	// Must contain blog-like path segments
	blogPaths := []string{"/posts/", "/post/", "/blog/", "/article/", "/articles/", "/news/", "/story/"}
	for _, path := range blogPaths {
		if strings.Contains(lower, path) {
			return true
		}
	}

	// Check for year patterns like /2024/ or /2025/
	yearPattern := regexp.MustCompile(`/20[12]\d/`)
	return yearPattern.MatchString(urlStr)
}

// resolveURL resolves a potentially relative URL against a base.
func resolveURL(base *url.URL, ref string) string {
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return base.ResolveReference(refURL).String()
}

// extractDateFromURL extracts an ISO date from a URL containing year/month/day patterns.
func extractDateFromURL(urlStr string) string {
	// Look for /YYYY/MM/DD/ or /YYYY-MM-DD/ patterns
	datePattern := regexp.MustCompile(`/(20[12]\d)[/-]?(\d{2})?[/-]?(\d{2})?/`)
	if m := datePattern.FindStringSubmatch(urlStr); len(m) > 1 {
		year := m[1]
		month := "01"
		day := "01"
		if len(m) > 2 && m[2] != "" {
			month = m[2]
		}
		if len(m) > 3 && m[3] != "" {
			day = m[3]
		}
		return fmt.Sprintf("%s-%s-%s", year, month, day)
	}
	return ""
}

// cleanEmail removes anti-spam text from email addresses.
func cleanEmail(email string) string {
	// Remove "NOSPAM" (case-insensitive) from email addresses
	lower := strings.ToLower(email)
	if strings.Contains(lower, "nospam") {
		// Find position of "nospam" and remove it
		idx := strings.Index(lower, "nospam")
		return email[:idx] + email[idx+6:]
	}
	return email
}

func dedupeLinks(links []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, link := range links {
		normalized := strings.TrimSuffix(strings.ToLower(link), "/")
		if !seen[normalized] {
			seen[normalized] = true
			result = append(result, link)
		}
	}
	return result
}

// isBotProtectionPage detects pages that are bot protection challenges rather than actual content.
// These pages return HTTP 200 but don't contain the profile we're looking for.
func isBotProtectionPage(body []byte) bool {
	content := strings.ToLower(string(body))

	// Very short pages are often challenges
	if len(body) < 500 {
		// Check for common challenge indicators
		if strings.Contains(content, "javascript") && strings.Contains(content, "enable") {
			return true
		}
	}

	// PyPI "Client Challenge" page
	if strings.Contains(content, "client challenge") {
		return true
	}

	// Cloudflare challenge indicators
	if strings.Contains(content, "checking your browser") ||
		strings.Contains(content, "cf-browser-verification") ||
		strings.Contains(content, "cf_chl_opt") {
		return true
	}

	// Generic bot protection indicators
	if strings.Contains(content, "please verify you are a human") ||
		strings.Contains(content, "verify you are human") ||
		strings.Contains(content, "access denied") && strings.Contains(content, "bot") {
		return true
	}

	// DataDome and similar
	if strings.Contains(content, "datadome") && strings.Contains(content, "captcha") {
		return true
	}

	return false
}

// validateURL checks for SSRF vulnerabilities and non-profile paths.
func validateURL(urlStr string) error {
	parsed, err := url.Parse(urlStr)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	// Block common non-profile paths
	path := strings.ToLower(parsed.Path)
	if strings.HasSuffix(path, "/support") || path == "/support" {
		return errors.New("blocked: support page")
	}

	host := strings.ToLower(parsed.Hostname())

	// Block localhost and local domains
	if host == "localhost" || host == "127.0.0.1" || host == "::1" ||
		strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return errors.New("blocked: local host")
	}

	// Block private IP ranges
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return errors.New("blocked: private IP")
		}
	}

	// Block metadata service endpoints
	if host == "169.254.169.254" || host == "metadata.google.internal" || host == "metadata.azure.com" {
		return errors.New("blocked: metadata service")
	}

	return nil
}
