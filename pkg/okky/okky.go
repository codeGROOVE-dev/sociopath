// Package okky fetches Okky (Korean developer community) user profile data.
package okky

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "okky"

// platformInfo implements profile.Platform for Okky.
type platformInfo struct{}

func (platformInfo) Name() string {
	return platform
}

func (platformInfo) Type() profile.PlatformType {
	return profile.PlatformTypeForum
}

func (platformInfo) Match(url string) bool {
	return Match(url)
}

func (platformInfo) AuthRequired() bool {
	return AuthRequired()
}

func init() {
	profile.Register(platformInfo{})
}

var usernamePattern = regexp.MustCompile(`(?i)okky\.kr/users/(\d+)`)

// Match returns true if the URL is an Okky user profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "okky.kr/users/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Okky profiles are public.
func AuthRequired() bool { return false }

// Client handles Okky requests.
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

// New creates an Okky client.
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

// nextData represents the Next.js data structure.
type nextData struct {
	Props struct {
		PageProps struct {
			Avatar struct {
				Nickname               string `json:"nickname"`
				OneLineSelfIntro       string `json:"oneLineSelfIntroduction"`
				Picture                string `json:"picture"`
				PictureType            string `json:"pictureType"`
			} `json:"avatar"`
			SocialLinkFirst  string `json:"socialLinkFirst"`
			SocialLinkSecond string `json:"socialLinkSecond"`
			SocialLinkThird  string `json:"socialLinkThird"`
			Activities       []struct {
				Title     string `json:"title"`
				Content   string `json:"content"`
				URL       string `json:"url"`
				CreatedAt string `json:"createdAt"`
				Type      string `json:"type"`
			} `json:"activities"`
			Counts struct {
				Posts  int `json:"posts"`
				Saved  int `json:"saved"`
				Awards int `json:"awards"`
			} `json:"counts"`
		} `json:"pageProps"`
	} `json:"props"`
}

// Fetch retrieves an Okky user profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	userID := extractUserID(urlStr)
	if userID == "" {
		return nil, fmt.Errorf("could not extract user ID from: %s", urlStr)
	}

	// Normalize URL to activity page
	normalizedURL := fmt.Sprintf("https://okky.kr/users/%s/activity", userID)
	c.logger.InfoContext(ctx, "fetching okky profile", "url", normalizedURL, "user_id", userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, normalizedURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, urlStr, userID, c.logger)
}

func parseProfile(htmlBytes []byte, url, userID string, logger *slog.Logger) (*profile.Profile, error) {
	htmlStr := string(htmlBytes)

	prof := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: userID,
		Fields:   make(map[string]string),
	}

	// Extract Next.js JSON data from __NEXT_DATA__ script tag
	nextDataPattern := regexp.MustCompile(`<script id="__NEXT_DATA__" type="application/json">(.*?)</script>`)
	matches := nextDataPattern.FindStringSubmatch(htmlStr)
	if len(matches) < 2 {
		logger.Warn("could not find __NEXT_DATA__ in HTML")
		// Return basic profile with just URL
		return prof, nil
	}

	var data nextData
	if err := json.Unmarshal([]byte(matches[1]), &data); err != nil {
		logger.Warn("failed to parse __NEXT_DATA__ JSON", "error", err)
		return prof, nil
	}

	// Extract profile data from JSON
	avatar := data.Props.PageProps.Avatar

	// Username/nickname
	if avatar.Nickname != "" {
		prof.Username = avatar.Nickname
		prof.DisplayName = avatar.Nickname
	}

	// Bio
	if avatar.OneLineSelfIntro != "" {
		prof.Bio = avatar.OneLineSelfIntro
	}

	// Avatar URL (construct from Gravatar)
	if avatar.Picture != "" {
		if avatar.PictureType == "GRAVATAR" {
			// Gravatar hash is provided - construct URL
			prof.AvatarURL = fmt.Sprintf("https://www.gravatar.com/avatar/%s", avatar.Picture)
		} else {
			// Direct URL or other type
			prof.AvatarURL = avatar.Picture
		}
	}

	// Social links
	if data.Props.PageProps.SocialLinkFirst != "" {
		prof.SocialLinks = append(prof.SocialLinks, data.Props.PageProps.SocialLinkFirst)
	}
	if data.Props.PageProps.SocialLinkSecond != "" {
		prof.SocialLinks = append(prof.SocialLinks, data.Props.PageProps.SocialLinkSecond)
	}
	if data.Props.PageProps.SocialLinkThird != "" {
		prof.SocialLinks = append(prof.SocialLinks, data.Props.PageProps.SocialLinkThird)
	}

	// Activity stats
	counts := data.Props.PageProps.Counts
	if counts.Posts > 0 {
		prof.Fields["posts"] = fmt.Sprintf("%d", counts.Posts)
	}
	if counts.Saved > 0 {
		prof.Fields["saved"] = fmt.Sprintf("%d", counts.Saved)
	}
	if counts.Awards > 0 {
		prof.Fields["awards"] = fmt.Sprintf("%d", counts.Awards)
	}

	// Extract posts/activities (limit to 10)
	activities := data.Props.PageProps.Activities
	if len(activities) > 10 {
		activities = activities[:10]
	}

	for _, activity := range activities {
		post := profile.Post{
			Type:  profile.PostTypeComment, // Default to comment
			Title: activity.Title,
			Content: activity.Content,
			URL:   activity.URL,
			Date:  activity.CreatedAt,
		}

		// Determine post type
		if activity.Type == "article" || activity.Type == "post" {
			post.Type = profile.PostTypeArticle
		} else if activity.Type == "question" {
			post.Type = profile.PostTypeQuestion
		}

		// Truncate content if too long
		if len(post.Content) > 200 {
			post.Content = post.Content[:200] + "..."
		}

		prof.Posts = append(prof.Posts, post)
	}

	return prof, nil
}

func extractUserID(urlStr string) string {
	// Extract user ID from URL pattern: okky.kr/users/{id}/*
	if matches := usernamePattern.FindStringSubmatch(urlStr); len(matches) > 1 {
		return matches[1]
	}
	return ""
}

// md5Hash returns the MD5 hash of the input string (for gravatar).
func md5Hash(text string) string {
	hash := md5.Sum([]byte(strings.ToLower(strings.TrimSpace(text))))
	return fmt.Sprintf("%x", hash)
}
