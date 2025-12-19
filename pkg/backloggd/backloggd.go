// Package backloggd fetches Backloggd gaming profile data.
// Backloggd is a game tracking and review platform similar to Letterboxd for movies.
package backloggd

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "backloggd"

type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeGaming }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.RegisterWithFetcher(platformInfo{}, fetchProfile) }

var usernamePattern = regexp.MustCompile(`backloggd\.com/u/([a-zA-Z0-9_-]+)`)

func Match(urlStr string) bool {
	return strings.Contains(urlStr, "backloggd.com/u/") && usernamePattern.MatchString(urlStr)
}

type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

type Option func(*config)
type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

func WithHTTPCache(c httpcache.Cacher) Option { return func(cfg *config) { cfg.cache = c } }
func WithLogger(l *slog.Logger) Option        { return func(cfg *config) { cfg.logger = l } }

func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}
	return &Client{
		httpClient: &http.Client{Timeout: 15 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching backloggd profile", "url", urlStr, "username", username)

	profileURL := fmt.Sprintf("https://www.backloggd.com/u/%s/", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, profileURL, username)
}

func parseProfile(body []byte, profileURL, username string) (*profile.Profile, error) {
	html := string(body)
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract display name
	nameRe := regexp.MustCompile(`<h1[^>]*class="[^"]*profile-name[^"]*"[^>]*>([^<]+)</h1>`)
	if matches := nameRe.FindStringSubmatch(html); len(matches) > 1 {
		p.DisplayName = strings.TrimSpace(matches[1])
	}
	if p.DisplayName == "" {
		p.DisplayName = username
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+class="[^"]*profile-avatar[^"]*"[^>]+src="([^"]+)"`)
	if matches := avatarRe.FindStringSubmatch(html); len(matches) > 1 {
		p.AvatarURL = matches[1]
		if strings.HasPrefix(p.AvatarURL, "//") {
			p.AvatarURL = "https:" + p.AvatarURL
		}
	}

	// Extract bio
	bioRe := regexp.MustCompile(`(?s)<div[^>]+class="[^"]*profile-bio[^"]*"[^>]*>(.*?)</div>`)
	if matches := bioRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Bio = strings.TrimSpace(htmlutil.StripTags(matches[1]))
	}

	// Extract location
	locationRe := regexp.MustCompile(`(?i)<i[^>]+class="[^"]*fa-map-marker[^"]*"[^>]*></i>\s*([^<]+)`)
	if matches := locationRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Location = strings.TrimSpace(matches[1])
	}

	// Extract member since
	memberRe := regexp.MustCompile(`(?i)Member since[:\s]*([^<]+)</`)
	if matches := memberRe.FindStringSubmatch(html); len(matches) > 1 {
		p.CreatedAt = strings.TrimSpace(matches[1])
	}

	// Extract stats - games played, reviews, lists
	gamesRe := regexp.MustCompile(`(?i)([0-9,]+)\s*(?:game|play)s?\s*played`)
	if matches := gamesRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["games_played"] = strings.ReplaceAll(matches[1], ",", "")
	}

	reviewsRe := regexp.MustCompile(`(?i)([0-9,]+)\s*reviews?`)
	if matches := reviewsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["reviews"] = strings.ReplaceAll(matches[1], ",", "")
	}

	listsRe := regexp.MustCompile(`(?i)([0-9,]+)\s*lists?`)
	if matches := listsRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["lists"] = strings.ReplaceAll(matches[1], ",", "")
	}

	followersRe := regexp.MustCompile(`(?i)([0-9,]+)\s*followers?`)
	if matches := followersRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["followers"] = strings.ReplaceAll(matches[1], ",", "")
	}

	followingRe := regexp.MustCompile(`(?i)([0-9,]+)\s*following`)
	if matches := followingRe.FindStringSubmatch(html); len(matches) > 1 {
		p.Fields["following"] = strings.ReplaceAll(matches[1], ",", "")
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(html)

	// Extract emails
	emails := htmlutil.EmailAddresses(html)
	if len(emails) > 0 {
		p.Fields["email"] = emails[0]
	}

	// Extract recent reviews as posts
	reviewPattern := regexp.MustCompile(`(?s)<div[^>]+class="[^"]*game-review[^"]*"[^>]*>.*?<a[^>]+href="(/games/[^"]+)"[^>]*>([^<]+)</a>.*?<div[^>]+class="[^"]*review-text[^"]*"[^>]*>(.*?)</div>`)
	reviews := reviewPattern.FindAllStringSubmatch(html, -1)
	for _, review := range reviews {
		if len(review) > 3 {
			gameURL := "https://www.backloggd.com" + review[1]
			gameTitle := strings.TrimSpace(review[2])
			reviewText := strings.TrimSpace(htmlutil.StripTags(review[3]))

			if reviewText != "" {
				p.Posts = append(p.Posts, profile.Post{
					Type:    profile.PostTypePost,
					Title:   "Review: " + gameTitle,
					Content: reviewText,
					URL:     gameURL,
				})
			}
		}
	}

	// Validate we found minimal data
	if p.DisplayName == "" && len(p.Posts) == 0 && p.AvatarURL == "" {
		return nil, profile.ErrProfileNotFound
	}

	return p, nil
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}

func fetchProfile(ctx context.Context, url string, cfg *profile.FetcherConfig) (*profile.Profile, error) {
	var opts []Option
	if cfg != nil {
		if cfg.Logger != nil {
			opts = append(opts, WithLogger(cfg.Logger))
		}
		if c, ok := cfg.Cache.(httpcache.Cacher); ok {
			opts = append(opts, WithHTTPCache(c))
		}
	}
	client, err := New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}
