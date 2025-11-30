// Package reddit fetches Reddit user profile data.
package reddit

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/cache"
	"github.com/codeGROOVE-dev/sociopath/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/profile"
)

const platform = "reddit"

// Match returns true if the URL is a Reddit user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "reddit.com/user/") ||
		strings.Contains(lower, "reddit.com/u/")
}

// AuthRequired returns false because Reddit profiles are public.
func AuthRequired() bool { return false }

// Client handles Reddit requests.
type Client struct {
	httpClient *http.Client
	cache      cache.HTTPCache
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  cache.HTTPCache
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache cache.HTTPCache) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a Reddit client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves a Reddit profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	// Normalize to old.reddit.com for simpler HTML parsing
	normalizedURL := fmt.Sprintf("https://old.reddit.com/user/%s", username)
	c.logger.InfoContext(ctx, "fetching reddit profile", "url", normalizedURL, "username", username)

	// Check cache
	var content string
	if c.cache != nil {
		if data, _, _, found := c.cache.Get(ctx, normalizedURL); found {
			content = string(data)
		}
	}

	if content == "" {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer func() { _ = resp.Body.Close() }() //nolint:errcheck // error ignored intentionally

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20)) // 5MB limit
		if err != nil {
			return nil, err
		}
		content = string(body)

		// Cache response
		if c.cache != nil {
			_ = c.cache.SetAsync(ctx, normalizedURL, body, "", nil) //nolint:errcheck // error ignored intentionally
		}
	}

	return parseProfile(content, normalizedURL, username)
}

func parseProfile(html, url, username string) (*profile.Profile, error) { //nolint:unparam // error return part of interface pattern
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract name from title
	prof.Name = htmlutil.Title(html)
	if prof.Name != "" {
		// Clean up "overview for username - Reddit"
		prof.Name = strings.TrimPrefix(prof.Name, "overview for ")
		if idx := strings.Index(prof.Name, " - Reddit"); idx != -1 {
			prof.Name = strings.TrimSpace(prof.Name[:idx])
		}
	}
	if prof.Name == "" {
		prof.Name = username
	}

	// Extract karma
	karmaPattern := regexp.MustCompile(`(\d+(?:,\d+)?)\s*(?:post|link)\s*karma`)
	if matches := karmaPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["post_karma"] = strings.ReplaceAll(matches[1], ",", "")
	}

	commentKarmaPattern := regexp.MustCompile(`(\d+(?:,\d+)?)\s*comment\s*karma`)
	if matches := commentKarmaPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["comment_karma"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract cake day (account creation date)
	cakeDayPattern := regexp.MustCompile(`(?i)redditor since.*?(\d{4})`)
	if matches := cakeDayPattern.FindStringSubmatch(html); len(matches) > 1 {
		prof.Fields["joined_year"] = matches[1]
	}

	// Extract subreddits and comment samples
	subreddits := extractSubreddits(html)
	if len(subreddits) > 0 {
		prof.Fields["subreddits"] = strings.Join(subreddits, ", ")
	}

	// Extract comment samples (for keyword/organization matching)
	commentSamples := extractCommentSamples(html, 5)
	if len(commentSamples) > 0 {
		prof.Unstructured = strings.Join(commentSamples, "\n\n---\n\n")
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(html)

	// Filter out Reddit's own links
	var filtered []string
	for _, link := range prof.SocialLinks {
		if !strings.Contains(link, "reddit.com") &&
			!strings.Contains(link, "redd.it") &&
			!strings.Contains(link, "redditblog.com") {
			filtered = append(filtered, link)
		}
	}
	prof.SocialLinks = filtered

	return prof, nil
}

func extractUsername(urlStr string) string {
	// Remove protocol
	urlStr = strings.TrimPrefix(urlStr, "https://")
	urlStr = strings.TrimPrefix(urlStr, "http://")

	// Extract reddit.com/user/username or reddit.com/u/username
	re := regexp.MustCompile(`reddit\.com/(?:user|u)/([^/?#]+)`)
	if matches := re.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// extractSubreddits extracts subreddit names from Reddit profile HTML.
func extractSubreddits(html string) []string {
	// Extract from data-subreddit attributes in comment/post divs
	pattern := regexp.MustCompile(`data-subreddit="([^"]+)"`)
	matches := pattern.FindAllStringSubmatch(html, -1)

	seen := make(map[string]bool)
	var subreddits []string

	for _, match := range matches {
		if len(match) > 1 {
			sub := match[1]
			// Skip user profiles (like u_username)
			if strings.HasPrefix(sub, "u_") {
				continue
			}
			// Skip generic/common subreddits
			if isGenericSubreddit(sub) {
				continue
			}
			if !seen[sub] {
				seen[sub] = true
				subreddits = append(subreddits, sub)
			}
		}
	}

	// Limit to top 10 most relevant subreddits
	if len(subreddits) > 10 {
		subreddits = subreddits[:10]
	}

	return subreddits
}

// isGenericSubreddit returns true for very common/generic subreddits that don't indicate interests.
func isGenericSubreddit(sub string) bool {
	generic := map[string]bool{
		"AskReddit": true, "pics": true, "funny": true, "movies": true,
		"gaming": true, "worldnews": true, "news": true, "todayilearned": true,
		"nottheonion": true, "explainlikeimfive": true, "mildlyinteresting": true,
		"DIY": true, "videos": true, "OldSchoolCool": true, "TwoXChromosomes": true,
		"tifu": true, "Music": true, "books": true, "LifeProTips": true,
		"dataisbeautiful": true, "aww": true, "science": true, "space": true,
		"Showerthoughts": true, "askscience": true, "Jokes": true, "IAmA": true,
		"Futurology": true, "sports": true, "UpliftingNews": true, "food": true,
		"nosleep": true, "creepy": true, "history": true, "gifs": true,
		"InternetIsBeautiful": true, "GetMotivated": true, "gadgets": true,
		"announcements": true, "WritingPrompts": true, "philosophy": true,
		"Documentaries": true, "EarthPorn": true, "photoshopbattles": true,
		"listentothis": true, "blog": true, "all": true, "popular": true,
		"reddit": true,
	}
	return generic[sub]
}

// extractCommentSamples extracts recent comment text samples from Reddit profile HTML.
func extractCommentSamples(html string, limit int) []string {
	// Extract text from comment divs with class="md" - use non-greedy match and look for paragraph tags
	pattern := regexp.MustCompile(`<div class="md"><p>(.+?)</p>`)
	matches := pattern.FindAllStringSubmatch(html, -1)

	var samples []string
	for _, match := range matches {
		if len(match) > 1 && len(samples) < limit {
			// Extract text from HTML, removing tags
			text := stripHTML(match[1])
			text = strings.TrimSpace(text)

			// Skip very short comments
			if len(text) < 20 {
				continue
			}

			// Skip generic messages
			if strings.Contains(text, "archived post") ||
				strings.Contains(text, "automatically archived") {
				continue
			}

			// Limit length of each sample to ~200 chars
			if len(text) > 200 {
				text = text[:200] + "..."
			}

			samples = append(samples, text)
		}
	}

	return samples
}

// stripHTML removes HTML tags from a string (simple implementation).
func stripHTML(s string) string {
	// Remove HTML tags
	tagPattern := regexp.MustCompile(`<[^>]*>`)
	s = tagPattern.ReplaceAllString(s, "")

	// Decode HTML entities
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	s = strings.ReplaceAll(s, "&nbsp;", " ")

	return s
}
