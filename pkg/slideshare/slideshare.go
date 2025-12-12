// Package slideshare fetches SlideShare profile data.
package slideshare

import (
	"context"
	"encoding/json"
	"errors"
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

const platform = "slideshare"

var usernamePattern = regexp.MustCompile(`(?i)slideshare\.net/([a-zA-Z0-9_-]+)(?:/|$|\?)`)

// Match returns true if the URL is a SlideShare profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "slideshare.net/") {
		return false
	}
	// Exclude non-profile paths
	if strings.Contains(lower, "/slideshow/") || strings.Contains(lower, "/category/") ||
		strings.Contains(lower, "/search/") || strings.Contains(lower, "/api/") ||
		strings.Contains(lower, "/features") || strings.Contains(lower, "/about") {
		return false
	}
	return usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because SlideShare profiles are public.
func AuthRequired() bool { return false }

// Client handles SlideShare requests.
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

// New creates a SlideShare client.
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

// nextData represents the __NEXT_DATA__ JSON structure.
type nextData struct {
	Props struct {
		PageProps struct {
			User    *userData    `json:"user"`
			Results *resultsData `json:"results"`
		} `json:"pageProps"`
	} `json:"props"`
}

//nolint:govet // fieldalignment not critical for JSON parsing
type userData struct {
	ID             string `json:"id"`
	Login          string `json:"login"`
	Name           string `json:"name"`
	Photo          string `json:"photo"`
	Description    string `json:"description"`
	City           string `json:"city"`
	Country        string `json:"country"`
	Organization   string `json:"organization"`
	Occupation     string `json:"occupation"`
	URL            string `json:"url"`
	SlideshowCount int    `json:"slideshowCount"`
	FollowersCount int    `json:"followersCount"`
	FollowingCount int    `json:"followingCount"`
	MoreInfo       *struct {
		TwitterHandle string `json:"twitterHandle"`
		FacebookURL   string `json:"facebookUrl"`
		LinkedinURL   string `json:"linkedinUrl"`
	} `json:"moreInfo"`
}

type resultsData struct {
	InitialResults []slideshow `json:"initialResults"`
}

//nolint:govet // fieldalignment not critical for JSON parsing
type slideshow struct {
	ID           string `json:"id"`
	Title        string `json:"title"`
	TotalSlides  int    `json:"totalSlides"`
	ViewCount    int    `json:"viewCount"`
	CanonicalURL string `json:"canonicalUrl"`
	Thumbnail    string `json:"thumbnail"`
	Type         string `json:"type"`
}

// Fetch retrieves a SlideShare profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching slideshare profile", "url", urlStr, "username", username)

	// Normalize URL
	profileURL := fmt.Sprintf("https://www.slideshare.net/%s", username)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseHTML(ctx, body, profileURL, c.logger)
}

func parseHTML(ctx context.Context, body []byte, profileURL string, logger *slog.Logger) (*profile.Profile, error) {
	content := string(body)

	// Extract __NEXT_DATA__ JSON
	nextDataStart := strings.Index(content, `<script id="__NEXT_DATA__" type="application/json">`)
	if nextDataStart == -1 {
		return nil, errors.New("could not find __NEXT_DATA__ in page")
	}
	nextDataStart += len(`<script id="__NEXT_DATA__" type="application/json">`)
	nextDataEnd := strings.Index(content[nextDataStart:], `</script>`)
	if nextDataEnd == -1 {
		return nil, errors.New("could not find end of __NEXT_DATA__")
	}

	var data nextData
	if err := json.Unmarshal([]byte(content[nextDataStart:nextDataStart+nextDataEnd]), &data); err != nil {
		return nil, fmt.Errorf("failed to parse __NEXT_DATA__: %w", err)
	}

	if data.Props.PageProps.User == nil {
		return nil, profile.ErrProfileNotFound
	}

	user := data.Props.PageProps.User
	p := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: user.Login,
		Name:     user.Name,
		Bio:      user.Description,
		Fields:   make(map[string]string),
	}

	// Use login as name if name is just the username
	if p.Name == p.Username || p.Name == "" {
		p.Name = user.Login
	}

	if user.Photo != "" && !strings.Contains(user.Photo, "profile-picture.png") {
		p.AvatarURL = user.Photo
	}

	if user.City != "" || user.Country != "" {
		location := strings.TrimSpace(user.City + ", " + user.Country)
		location = strings.Trim(location, ", ")
		if location != "" {
			p.Location = location
		}
	}

	if user.Organization != "" {
		p.Fields["organization"] = user.Organization
	}
	if user.Occupation != "" {
		p.Fields["occupation"] = user.Occupation
	}
	if user.URL != "" {
		p.Website = user.URL
		p.SocialLinks = append(p.SocialLinks, user.URL)
	}

	p.Fields["followers"] = strconv.Itoa(user.FollowersCount)
	p.Fields["slideshows"] = strconv.Itoa(user.SlideshowCount)

	// Extract social links
	if user.MoreInfo != nil {
		if user.MoreInfo.TwitterHandle != "" {
			twitterURL := "https://twitter.com/" + user.MoreInfo.TwitterHandle
			p.SocialLinks = append(p.SocialLinks, twitterURL)
		}
		if user.MoreInfo.FacebookURL != "" {
			p.SocialLinks = append(p.SocialLinks, user.MoreInfo.FacebookURL)
		}
		if user.MoreInfo.LinkedinURL != "" {
			p.SocialLinks = append(p.SocialLinks, user.MoreInfo.LinkedinURL)
		}
	}

	// Extract presentations as posts
	if data.Props.PageProps.Results != nil {
		for i, slide := range data.Props.PageProps.Results.InitialResults {
			if i >= 10 {
				break
			}
			if slide.Title == "" || slide.CanonicalURL == "" {
				continue
			}
			p.Posts = append(p.Posts, profile.Post{
				Type:  profile.PostTypeArticle,
				Title: slide.Title,
				URL:   slide.CanonicalURL,
			})
			logger.DebugContext(ctx, "extracted slideshare presentation",
				"title", slide.Title, "views", slide.ViewCount, "slides", slide.TotalSlides)
		}
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
