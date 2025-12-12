// Package huggingface fetches HuggingFace user profile data.
package huggingface

import (
	"context"
	"encoding/json"
	"html"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "huggingface"

var usernamePattern = regexp.MustCompile(`(?i)huggingface\.co/([a-zA-Z0-9_-]+)/?(?:\?|$|#)`)

// Match returns true if the URL is a HuggingFace profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "huggingface.co/") {
		return false
	}
	// Skip non-profile pages
	skipPaths := []string{"/spaces/", "/datasets/", "/models/", "/docs/", "/blog/", "/papers/", "/collections/"}
	for _, sp := range skipPaths {
		if strings.Contains(lower, sp) {
			return false
		}
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because HuggingFace profiles are public.
func AuthRequired() bool { return false }

// Client handles HuggingFace requests.
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

// New creates a HuggingFace client.
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

// Fetch retrieves a HuggingFace profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, profile.ErrProfileNotFound
	}

	profileURL := "https://huggingface.co/" + username
	c.logger.InfoContext(ctx, "fetching huggingface profile", "url", profileURL, "username", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "text/html")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	// Check for 404 page
	if strings.Contains(string(body), "Page not found") {
		return nil, profile.ErrProfileNotFound
	}

	return parseHTML(body, username, profileURL)
}

func parseHTML(body []byte, username, urlStr string) (*profile.Profile, error) {
	content := string(body)

	prof := &profile.Profile{
		Platform: platform,
		URL:      urlStr,
		Username: username,
		Fields:   make(map[string]string),
	}

	// Extract UserProfile data-props JSON
	dataPropsPattern := regexp.MustCompile(`data-target="UserProfile" data-props="([^"]+)"`)
	match := dataPropsPattern.FindStringSubmatch(content)
	if match == nil {
		return nil, profile.ErrProfileNotFound
	}

	// Decode HTML entities and parse JSON
	jsonStr := html.UnescapeString(match[1])
	var data userProfileData
	if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
		return nil, profile.ErrProfileNotFound
	}

	// Extract user info
	if data.User.Fullname != "" {
		prof.Name = data.User.Fullname
	}
	if data.User.AvatarURL != "" {
		prof.AvatarURL = data.User.AvatarURL
	}

	// Extract social links from signup data
	extractSocialLinks(prof, data.User.Signup)

	// Extract posts as status updates
	var posts []string
	for _, post := range data.Posts {
		if post.RawContent != "" {
			text := strings.TrimSpace(post.RawContent)
			if len(text) > 200 {
				text = text[:200] + "..."
			}
			posts = append(posts, text)
		}
	}
	if len(posts) > 0 {
		prof.Fields["posts"] = strings.Join(posts, " | ")
	}

	// Extract paper titles
	var papers []string
	for _, paper := range data.Papers {
		if paper.Title != "" {
			papers = append(papers, strings.TrimSpace(paper.Title))
		}
	}
	if len(papers) > 0 {
		prof.Fields["papers"] = strings.Join(papers, " | ")
	}

	// Store counts
	if data.NumModels > 0 {
		prof.Fields["models"] = strconv.Itoa(data.NumModels)
	}
	if data.NumDatasets > 0 {
		prof.Fields["datasets"] = strconv.Itoa(data.NumDatasets)
	}
	if data.NumSpaces > 0 {
		prof.Fields["spaces"] = strconv.Itoa(data.NumSpaces)
	}
	if data.NumFollowers > 0 {
		prof.Fields["followers"] = strconv.Itoa(data.NumFollowers)
	}

	// Check for HF employee/admin status
	if data.User.IsHf {
		prof.Fields["hf_employee"] = "true"
	}
	if data.User.IsHfAdmin {
		prof.Fields["hf_admin"] = "true"
	}
	if data.User.IsPro {
		prof.Fields["pro"] = "true"
	}

	return prof, nil
}

func extractSocialLinks(prof *profile.Profile, signup signupInfo) {
	if signup.GitHub != "" {
		url := "https://github.com/" + signup.GitHub
		prof.Fields["github"] = url
		prof.SocialLinks = append(prof.SocialLinks, url)
	}
	if signup.Twitter != "" {
		url := "https://twitter.com/" + signup.Twitter
		prof.Fields["twitter"] = url
		prof.SocialLinks = append(prof.SocialLinks, url)
	}
	if signup.LinkedIn != "" {
		url := "https://linkedin.com/in/" + signup.LinkedIn
		prof.Fields["linkedin"] = url
		prof.SocialLinks = append(prof.SocialLinks, url)
	}
	if signup.Bluesky != "" {
		url := "https://bsky.app/profile/" + signup.Bluesky
		prof.Fields["bluesky"] = url
		prof.SocialLinks = append(prof.SocialLinks, url)
	}
	if signup.Homepage != "" {
		prof.Website = signup.Homepage
		prof.Fields["website"] = signup.Homepage
	}
}

type userProfileData struct {
	User         userInfo `json:"u"`
	Posts        []post   `json:"posts"`
	Papers       []paper  `json:"papers"`
	NumModels    int      `json:"numModels"`
	NumDatasets  int      `json:"numDatasets"`
	NumSpaces    int      `json:"numSpaces"`
	NumFollowers int      `json:"numFollowers"`
}

type userInfo struct {
	Signup    signupInfo `json:"signup"`
	ID        string     `json:"_id"`
	Name      string     `json:"name"`
	Fullname  string     `json:"fullname"`
	AvatarURL string     `json:"avatarUrl"`
	IsPro     bool       `json:"isPro"`
	IsHf      bool       `json:"isHf"`
	IsHfAdmin bool       `json:"isHfAdmin"`
}

type signupInfo struct {
	GitHub   string `json:"github"`
	Twitter  string `json:"twitter"`
	LinkedIn string `json:"linkedin"`
	Bluesky  string `json:"bluesky"`
	Homepage string `json:"homepage"`
}

type post struct {
	Slug       string `json:"slug"`
	RawContent string `json:"rawContent"`
}

type paper struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

func extractUsername(urlStr string) string {
	matches := usernamePattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
