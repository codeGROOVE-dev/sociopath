// Package leetcode fetches LeetCode user profile data.
package leetcode

import (
	"bytes"
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

const platform = "leetcode"

var usernamePattern = regexp.MustCompile(`(?i)leetcode\.com/(?:u/)?([a-zA-Z0-9_-]+)`)

// Match returns true if the URL is a LeetCode profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "leetcode.com/") {
		return false
	}
	// Exclude non-profile paths
	excluded := []string{"/problems/", "/contest/", "/discuss/", "/playground/", "/explore/", "/study-plan/"}
	for _, ex := range excluded {
		if strings.Contains(lower, ex) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because LeetCode profiles are public.
func AuthRequired() bool { return false }

// Client handles LeetCode requests.
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

// New creates a LeetCode client.
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

const graphQLQuery = `query($username: String!) {
  matchedUser(username: $username) {
    username
    profile {
      realName
      aboutMe
      userAvatar
      skillTags
      websites
      ranking
      company
      school
    }
    socialAccounts
  }
}`

// graphQLRequest represents the GraphQL query structure.
//
//nolint:govet // fieldalignment: struct ordering for JSON readability
type graphQLRequest struct {
	Query     string         `json:"query"`
	Variables map[string]any `json:"variables"`
}

// graphQLResponse represents the GraphQL response structure.
type graphQLResponse struct {
	Data struct {
		MatchedUser *apiUser `json:"matchedUser"`
	} `json:"data"`
	Errors []struct {
		Message string `json:"message"`
	} `json:"errors"`
}

// apiUser represents the LeetCode user data.
type apiUser struct {
	Username       string      `json:"username"`
	Profile        *apiProfile `json:"profile"`
	SocialAccounts []string    `json:"socialAccounts"`
}

//nolint:govet // fieldalignment: struct ordering for JSON readability
type apiProfile struct {
	RealName   string   `json:"realName"`
	AboutMe    string   `json:"aboutMe"`
	UserAvatar string   `json:"userAvatar"`
	SkillTags  []string `json:"skillTags"`
	Websites   []string `json:"websites"`
	Ranking    int      `json:"ranking"`
	Company    string   `json:"company"`
	School     string   `json:"school"`
}

// Fetch retrieves a LeetCode profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching leetcode profile", "url", urlStr, "username", username)

	reqBody := graphQLRequest{
		Query: graphQLQuery,
		Variables: map[string]any{
			"username": username,
		},
	}

	jsonBody, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://leetcode.com/graphql", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp graphQLResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse leetcode response: %w", err)
	}

	if len(resp.Errors) > 0 {
		return nil, fmt.Errorf("leetcode API error: %s", resp.Errors[0].Message)
	}

	if resp.Data.MatchedUser == nil || resp.Data.MatchedUser.Username == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.Data.MatchedUser, urlStr), nil
}

func parseProfile(data *apiUser, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Username,
		Fields:   make(map[string]string),
	}

	if data.Profile != nil {
		prof := data.Profile

		if prof.RealName != "" {
			p.Name = prof.RealName
		} else {
			p.Name = data.Username
		}

		if prof.AboutMe != "" {
			p.Bio = prof.AboutMe
		}

		if prof.UserAvatar != "" {
			p.AvatarURL = prof.UserAvatar
		}

		if prof.Ranking > 0 {
			p.Fields["ranking"] = strconv.Itoa(prof.Ranking)
		}

		if prof.Company != "" {
			p.Fields["company"] = prof.Company
		}

		if prof.School != "" {
			p.Fields["school"] = prof.School
		}

		if len(prof.SkillTags) > 0 {
			p.Fields["skills"] = strings.Join(prof.SkillTags, ", ")
		}

		// Websites as social links
		for _, website := range prof.Websites {
			if website != "" {
				p.SocialLinks = append(p.SocialLinks, website)
			}
		}
	} else {
		p.Name = data.Username
	}

	return p
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
