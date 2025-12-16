// Package stackoverflow fetches StackOverflow user profile data.
package stackoverflow

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/htmlutil"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "stackoverflow"

// platformInfo implements profile.Platform for StackOverflow.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a StackOverflow profile URL.
func Match(urlStr string) bool {
	return strings.Contains(strings.ToLower(urlStr), "stackoverflow.com/users/")
}

// AuthRequired returns false because StackOverflow profiles are public.
func AuthRequired() bool { return false }

// Client handles StackOverflow requests.
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

// New creates a StackOverflow client.
func New(ctx context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	cache := cfg.cache
	if cache == nil {
		cache = httpcache.NewNull()
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cache,
		logger: cfg.logger,
	}, nil
}

// apiResponse represents the Stack Exchange API wrapper.
type apiResponse struct {
	Items []apiQuestion `json:"items"`
}

// apiQuestion represents a question from the API.
type apiQuestion struct { //nolint:govet // field order matches API response
	Tags       []string `json:"tags"`
	Title      string   `json:"title"`
	Link       string   `json:"link"`
	QuestionID int      `json:"question_id"`
}

// apiAnswerResponse represents answers from the API.
type apiAnswerResponse struct {
	Items []apiAnswer `json:"items"`
}

// apiAnswer represents an answer from the API.
type apiAnswer struct {
	AnswerID   int `json:"answer_id"`
	QuestionID int `json:"question_id"`
	Score      int `json:"score"`
}

// Fetch retrieves a StackOverflow profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	userID := extractUserID(urlStr)

	c.logger.InfoContext(ctx, "fetching stackoverflow profile", "url", urlStr, "username", username, "user_id", userID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	p := parseHTML(body, urlStr, username)

	// Fetch recent questions and answers if we have a user ID
	if userID != "" {
		posts := c.fetchRecentPosts(ctx, userID, 10)
		p.Posts = posts
	}

	return p, nil
}

func parseHTML(data []byte, urlStr, username string) *profile.Profile {
	content := string(data)

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract name from title - format: "User Jon Skeet - Stack Overflow"
	title := htmlutil.Title(content)
	if name, found := strings.CutPrefix(title, "User "); found {
		if idx := strings.Index(name, " - "); idx != -1 {
			p.DisplayName = strings.TrimSpace(name[:idx])
		}
	}

	// Extract avatar URL from profile image
	avatarPattern := regexp.MustCompile(`<img[^>]+class="[^"]*s-avatar[^"]*"[^>]+src="([^"]+)"`)
	if m := avatarPattern.FindStringSubmatch(content); len(m) > 1 {
		p.AvatarURL = m[1]
	}

	// Extract location
	locPattern := regexp.MustCompile(`<div[^>]*class="[^"]*wmx2[^"]*truncate[^"]*"[^>]*title="([^"]+)"`)
	if m := locPattern.FindStringSubmatch(content); len(m) > 1 {
		loc := strings.TrimSpace(m[1])
		if len(loc) > 3 && len(loc) < 100 {
			p.Location = loc
			p.Fields["location"] = loc
		}
	}

	// Extract reputation
	repPattern := regexp.MustCompile(`(?i)<div[^>]*class="[^"]*fs-title[^"]*"[^>]*>\s*([\d,]+)\s*</div>\s*<div[^>]*>reputation</div>`)
	if m := repPattern.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["reputation"] = m[1]
	}

	// Extract top tags
	tagPattern := regexp.MustCompile(`(?i)<a[^>]*class="[^"]*post-tag[^"]*"[^>]*>([^<]+)</a>`)
	tagMatches := tagPattern.FindAllStringSubmatch(content, 5)
	var tags []string
	for _, m := range tagMatches {
		if len(m) > 1 && len(tags) < 5 {
			tags = append(tags, strings.TrimSpace(m[1]))
		}
	}
	if len(tags) > 0 {
		p.Fields["top_tags"] = strings.Join(tags, ", ")
	}

	// Use bio field for location display
	if p.Location != "" {
		p.Bio = p.Location
	}

	p.SocialLinks = htmlutil.SocialLinks(content)

	return p
}

func extractUsername(urlStr string) string {
	re := regexp.MustCompile(`/users/\d+/([^/?]+)`)
	if m := re.FindStringSubmatch(urlStr); len(m) > 1 {
		return m[1]
	}
	return ""
}

func extractUserID(urlStr string) string {
	re := regexp.MustCompile(`/users/(\d+)`)
	if m := re.FindStringSubmatch(urlStr); len(m) > 1 {
		return m[1]
	}
	return ""
}

// fetchRecentPosts fetches recent questions and answers from the Stack Exchange API.
func (c *Client) fetchRecentPosts(ctx context.Context, userID string, maxItems int) []profile.Post {
	var posts []profile.Post

	// Fetch recent questions
	questionsURL := "https://api.stackexchange.com/2.3/users/%s/questions?order=desc&sort=creation&site=stackoverflow&pagesize=%d"
	questions := c.fetchQuestions(ctx, fmt.Sprintf(questionsURL, userID, maxItems))
	for _, q := range questions {
		posts = append(posts, profile.Post{
			Type:  profile.PostTypeQuestion,
			Title: q.Title,
			URL:   q.Link,
		})
	}

	// Fetch recent answers
	answersURL := "https://api.stackexchange.com/2.3/users/%s/answers?order=desc&sort=creation&site=stackoverflow&pagesize=%d"
	answers := c.fetchAnswers(ctx, fmt.Sprintf(answersURL, userID, maxItems))
	for _, a := range answers {
		posts = append(posts, profile.Post{
			Type: profile.PostTypeAnswer,
			URL:  fmt.Sprintf("https://stackoverflow.com/a/%d", a.AnswerID),
		})
	}

	// Limit total posts
	if len(posts) > maxItems {
		posts = posts[:maxItems]
	}

	return posts
}

func (c *Client) fetchQuestions(ctx context.Context, apiURL string) []apiQuestion {
	body, err := c.fetchSEAPI(ctx, apiURL)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to fetch questions", "error", err)
		return nil
	}

	var apiResp apiResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		c.logger.DebugContext(ctx, "failed to parse questions response", "error", err)
		return nil
	}

	return apiResp.Items
}

func (c *Client) fetchAnswers(ctx context.Context, apiURL string) []apiAnswer {
	body, err := c.fetchSEAPI(ctx, apiURL)
	if err != nil {
		c.logger.DebugContext(ctx, "failed to fetch answers", "error", err)
		return nil
	}

	var apiResp apiAnswerResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		c.logger.DebugContext(ctx, "failed to parse answers response", "error", err)
		return nil
	}

	return apiResp.Items
}

// fetchSEAPI fetches from SE API with caching and gzip handling.
func (c *Client) fetchSEAPI(ctx context.Context, apiURL string) ([]byte, error) {
	fetch := func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "sociopath/1.0")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close() //nolint:errcheck // defer closes body

		if resp.StatusCode != http.StatusOK {
			return nil, &httpcache.HTTPError{StatusCode: resp.StatusCode, URL: apiURL}
		}

		return readCompressedBody(resp)
	}

	return c.cache.GetSet(ctx, httpcache.URLToKey(apiURL), fetch, c.cache.TTL())
}

// readCompressedBody reads a response body, handling gzip compression if present.
func readCompressedBody(resp *http.Response) ([]byte, error) {
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return nil, err
		}
		defer gr.Close() //nolint:errcheck // defer closes reader
		return io.ReadAll(gr)
	}
	return io.ReadAll(resp.Body)
}
