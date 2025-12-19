// Package wykop fetches Wykop.pl profile data.
// Wykop.pl is Poland's largest social news aggregator with a strong developer community.
package wykop

import (
	"context"
	"crypto/tls"
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

const platform = "wykop"

// platformInfo implements profile.Platform for Wykop.pl.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Wykop.pl profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "wykop.pl/") {
		return false
	}
	// Profile URLs are wykop.pl/ludzie/{username}
	return strings.Contains(lower, "/ludzie/")
}

// AuthRequired returns false because Wykop.pl profiles are public.
func AuthRequired() bool { return false }

// Client handles Wykop.pl requests.
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

// New creates a Wykop.pl client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // needed for corporate proxies
			},
		},
		cache:  cfg.cache,
		logger: cfg.logger,
	}, nil
}

// Fetch retrieves a Wykop.pl profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching wykop profile", "url", urlStr, "username", username)

	// Normalize to /ludzie/{username} format
	profileURL := fmt.Sprintf("https://wykop.pl/ludzie/%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "pl-PL,pl;q=0.9,en-US;q=0.8,en;q=0.7")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, profileURL, username)
}

// parseProfile extracts profile data from Wykop.pl HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "Nie znaleziono użytkownika") ||
	   strings.Contains(content, "User not found") ||
	   strings.Contains(content, "Profil nie istnieje") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		DisplayName:   username,
		Fields:        make(map[string]string),
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`<img[^>]+alt="@` + regexp.QuoteMeta(username) + `"[^>]+src="([^"]+)"`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 1 {
		avatar := m[1]
		if strings.HasPrefix(avatar, "//") {
			avatar = "https:" + avatar
		} else if !strings.HasPrefix(avatar, "http") {
			avatar = "https://wykop.pl" + avatar
		}
		p.AvatarURL = avatar
	}

	// Alternative avatar pattern
	if p.AvatarURL == "" {
		avatarRe2 := regexp.MustCompile(`<img[^>]+class="[^"]*avatar[^"]*"[^>]+src="([^"]+)"`)
		if m := avatarRe2.FindStringSubmatch(content); len(m) > 1 {
			avatar := m[1]
			if strings.HasPrefix(avatar, "//") {
				avatar = "https:" + avatar
			} else if !strings.HasPrefix(avatar, "http") {
				avatar = "https://wykop.pl" + avatar
			}
			p.AvatarURL = avatar
		}
	}

	// Extract account age/registration info
	accountAgeRe := regexp.MustCompile(`(?i)(?:na wykopie od|on wykop for)\s*(\d+)\s*(?:lat|lata|rok|year|years)`)
	if m := accountAgeRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["years_on_wykop"] = m[1]
	}

	// Extract rank/color
	rankRe := regexp.MustCompile(`kolor\s*:\s*([^,\s]+)`)
	if m := rankRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["rank"] = strings.TrimSpace(m[1])
	}

	// Extract posts count
	postsRe := regexp.MustCompile(`(\d+)\s*(?:wpis|wpisy|wpisów|post|posts)`)
	if m := postsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["posts"] = m[1]
	}

	// Extract links published count
	linksRe := regexp.MustCompile(`(\d+)\s*(?:link|linki|linków)`)
	if m := linksRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["links_published"] = m[1]
	}

	// Extract entries count
	entriesRe := regexp.MustCompile(`(\d+)\s*(?:entries|wpis)`)
	if m := entriesRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["entries"] = m[1]
	}

	// Extract bio/description if present
	bioRe := regexp.MustCompile(`<div[^>]*class="[^"]*profile-bio[^"]*"[^>]*>([\s\S]*?)</div>`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		bio := m[1]
		bio = regexp.MustCompile(`<[^>]+>`).ReplaceAllString(bio, "")
		p.Bio = strings.TrimSpace(bio)
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent posts/entries
	p.Posts = extractPosts(content)

	return p, nil
}

// extractPosts extracts recent posts and entries from the profile.
func extractPosts(content string) []profile.Post {
	var posts []profile.Post

	// Look for entries/posts
	entryRe := regexp.MustCompile(`<a[^>]+href="(/wpis/\d+[^"]*)"[^>]*>([^<]+)</a>`)
	matches := entryRe.FindAllStringSubmatch(content, 20)

	for _, m := range matches {
		if len(m) > 2 {
			title := strings.TrimSpace(m[2])
			if title == "" {
				continue
			}
			url := m[1]
			if !strings.HasPrefix(url, "http") {
				url = "https://wykop.pl" + url
			}

			posts = append(posts, profile.Post{
				Type:  profile.PostTypeComment,
				Title: title,
				URL:   url,
			})
		}
	}

	// Look for link submissions
	linkRe := regexp.MustCompile(`<a[^>]+href="(/link/\d+[^"]*)"[^>]*>([^<]+)</a>`)
	matches2 := linkRe.FindAllStringSubmatch(content, 20)

	for _, m := range matches2 {
		if len(m) > 2 {
			title := strings.TrimSpace(m[2])
			if title == "" {
				continue
			}
			url := m[1]
			if !strings.HasPrefix(url, "http") {
				url = "https://wykop.pl" + url
			}

			posts = append(posts, profile.Post{
				Type:  profile.PostTypeArticle,
				Title: title,
				URL:   url,
			})
		}
	}

	return posts
}

// extractUsername extracts username from Wykop.pl URL.
func extractUsername(urlStr string) string {
	// Handle wykop.pl/ludzie/{username}
	if idx := strings.Index(urlStr, "/ludzie/"); idx != -1 {
		username := urlStr[idx+len("/ludzie/"):]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}

	return ""
}
