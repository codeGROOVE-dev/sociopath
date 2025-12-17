// Package codewars fetches Codewars user profile data.
package codewars

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "codewars"

// platformInfo implements profile.Platform for Codewars.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)codewars\.com/users/([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a Codewars profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "codewars.com/users/") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Codewars profiles are public.
func AuthRequired() bool { return false }

// Client handles Codewars requests.
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

// New creates a Codewars client.
func New(_ context.Context, opts ...Option) (*Client, error) {
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

// apiResponse represents the Codewars API response.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type apiResponse struct {
	ID                  string   `json:"id"`
	Username            string   `json:"username"`
	Name                string   `json:"name"`
	Honor               int      `json:"honor"`
	Clan                string   `json:"clan"`
	LeaderboardPosition *int     `json:"leaderboardPosition"`
	Skills              []string `json:"skills"`
	Ranks               struct {
		Overall   apiRank            `json:"overall"`
		Languages map[string]apiRank `json:"languages"`
	} `json:"ranks"`
	CodeChallenges struct {
		TotalAuthored  int `json:"totalAuthored"`
		TotalCompleted int `json:"totalCompleted"`
	} `json:"codeChallenges"`
}

type apiRank struct {
	Name  string `json:"name"`
	Color string `json:"color"`
	Rank  int    `json:"rank"`
	Score int    `json:"score"`
}

// Fetch retrieves a Codewars profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching codewars profile", "url", urlStr, "username", username)

	// Fetch API and HTML in parallel
	apiData, apiErr := c.fetchAPI(ctx, username)
	html := c.fetchHTMLData(ctx, username)

	if apiErr != nil {
		return nil, apiErr
	}

	prof := parseProfile(apiData, html, urlStr)

	return prof, nil
}

func (c *Client) fetchAPI(ctx context.Context, username string) (*apiResponse, error) {
	apiURL := "https://www.codewars.com/api/v1/users/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse codewars response: %w", err)
	}

	if resp.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return &resp, nil
}

var socialLinkPattern = regexp.MustCompile(`<b>Profiles:</b>.*?<a href="([^"]+)"`)

// htmlData contains additional profile data extracted from HTML.
//
//nolint:govet // fieldalignment: struct ordering for logical grouping
type htmlData struct {
	socialLinks []string
	avatarURL   string
	memberSince string
	lastSeen    string
	following   string
	followers   string
	allies      string
}

func (c *Client) fetchHTMLData(ctx context.Context, username string) *htmlData {
	htmlURL := "https://www.codewars.com/users/" + username

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, htmlURL, http.NoBody)
	if err != nil {
		return &htmlData{}
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return &htmlData{}
	}

	content := string(body)
	data := &htmlData{}

	// Extract avatar URL
	// Format: <img ... alt="username Avatar" src="https://www.codewars.com/avatars/..." />
	avatarPattern := regexp.MustCompile(`<img[^>]+Avatar[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		data.avatarURL = m[1]
	}

	// Extract social links from the Profiles section
	matches := socialLinkPattern.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		if len(m) > 1 {
			data.socialLinks = append(data.socialLinks, m[1])
		}
	}

	// Extract additional profile fields
	// Format: <b>Member Since:</b>Jan 2021
	fieldPattern := regexp.MustCompile(`<b>(Member Since|Last Seen|Following|Followers|Allies):</b>([^<]+)`)
	fieldMatches := fieldPattern.FindAllStringSubmatch(content, -1)
	for _, m := range fieldMatches {
		if len(m) < 3 {
			continue
		}
		value := strings.TrimSpace(m[2])
		switch m[1] {
		case "Member Since":
			data.memberSince = value
		case "Last Seen":
			data.lastSeen = value
		case "Following":
			data.following = value
		case "Followers":
			data.followers = value
		case "Allies":
			data.allies = value
		default:
			// Ignore unknown fields
		}
	}

	return data
}

func parseProfile(data *apiResponse, html *htmlData, url string) *profile.Profile {
	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Username,
		Fields:   make(map[string]string),
	}

	if data.Name != "" {
		prof.DisplayName = data.Name
	} else {
		prof.DisplayName = data.Username
	}

	// Clan as a group membership
	if data.Clan != "" {
		prof.Groups = append(prof.Groups, data.Clan)
	}

	if data.Honor > 0 {
		prof.Fields["honor"] = strconv.Itoa(data.Honor)
	}

	if data.Ranks.Overall.Name != "" {
		// Parse rank like "6 kyu" or "2 dan" into badge format: kyu=6, dan=2
		parts := strings.SplitN(data.Ranks.Overall.Name, " ", 2)
		if len(parts) == 2 {
			prof.Badges = map[string]string{parts[1]: parts[0]}
		}
	}

	if data.CodeChallenges.TotalCompleted > 0 {
		prof.Fields["kata_completed"] = strconv.Itoa(data.CodeChallenges.TotalCompleted)
	}

	if data.CodeChallenges.TotalAuthored > 0 {
		prof.Fields["kata_authored"] = strconv.Itoa(data.CodeChallenges.TotalAuthored)
	}

	if data.LeaderboardPosition != nil && *data.LeaderboardPosition > 0 {
		prof.Fields["leaderboard_position"] = strconv.Itoa(*data.LeaderboardPosition)
	}

	if len(data.Skills) > 0 {
		prof.Fields["skills"] = strings.Join(data.Skills, ", ")
	}

	// Extract languages with ranks
	if len(data.Ranks.Languages) > 0 {
		var langs []string
		for lang, rank := range data.Ranks.Languages {
			langs = append(langs, fmt.Sprintf("%s (%s)", lang, rank.Name))
		}
		prof.Fields["languages"] = strings.Join(langs, ", ")
	}

	// Add HTML-extracted data
	if html != nil {
		if html.avatarURL != "" {
			prof.AvatarURL = html.avatarURL
		}
		if html.memberSince != "" {
			prof.CreatedAt = html.memberSince
		}
		if html.lastSeen != "" {
			prof.Fields["last_seen"] = html.lastSeen
		}
		if html.following != "" {
			prof.Fields["following"] = html.following
		}
		if html.followers != "" {
			prof.Fields["followers"] = html.followers
		}
		if html.allies != "" {
			prof.Fields["allies"] = html.allies
		}
		prof.SocialLinks = html.socialLinks
	}

	return prof
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
