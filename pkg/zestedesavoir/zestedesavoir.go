// Package zestedesavoir fetches Zeste de Savoir profile data.
// Zeste de Savoir is a French community-driven learning platform for tech and programming.
package zestedesavoir

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

const platform = "zestedesavoir"

// platformInfo implements profile.Platform for Zeste de Savoir.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// Match returns true if the URL is a Zeste de Savoir profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "zestedesavoir.com/") {
		return false
	}
	// Profile URLs are zestedesavoir.com/@username
	return strings.Contains(lower, "/@")
}

// AuthRequired returns false because Zeste de Savoir profiles are public.
func AuthRequired() bool { return false }

// Client handles Zeste de Savoir requests.
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

// New creates a Zeste de Savoir client.
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

// Fetch retrieves a Zeste de Savoir profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching zestedesavoir profile", "url", urlStr, "username", username)

	// Normalize to @username format
	profileURL := fmt.Sprintf("https://zestedesavoir.com/@%s", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "sociopath/1.0")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "fr-FR,fr;q=0.9,en;q=0.8")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	return parseProfile(body, profileURL, username)
}

// parseProfile extracts profile data from Zeste de Savoir HTML.
func parseProfile(data []byte, urlStr, username string) (*profile.Profile, error) {
	content := string(data)

	// Check if profile exists
	if strings.Contains(content, "Utilisateur introuvable") || strings.Contains(content, "User not found") {
		return nil, profile.ErrProfileNotFound
	}

	p := &profile.Profile{
		Platform:      platform,
		URL:           urlStr,
		Authenticated: false,
		Username:      username,
		Fields:        make(map[string]string),
	}

	// Extract display name from h1
	nameRe := regexp.MustCompile(`<h1[^>]*>([^<]+)</h1>`)
	if m := nameRe.FindStringSubmatch(content); len(m) > 1 {
		p.DisplayName = strings.TrimSpace(m[1])
	}

	// Extract avatar
	avatarRe := regexp.MustCompile(`/media/galleries/\d+/[a-f0-9-]+\.(?:jpg|png|gif)`)
	if m := avatarRe.FindStringSubmatch(content); len(m) > 0 {
		p.AvatarURL = "https://zestedesavoir.com" + m[0]
	}

	// Extract registration date
	registeredRe := regexp.MustCompile(`Inscrit(?:e)? le ([0-9]{1,2} [a-zéû]+ [0-9]{4})|Member since ([A-Za-z]+ [0-9]{1,2}, [0-9]{4})`)
	if m := registeredRe.FindStringSubmatch(content); len(m) > 1 {
		if m[1] != "" {
			p.CreatedAt = m[1]
		} else if m[2] != "" {
			p.CreatedAt = m[2]
		}
	}

	// Extract last activity date
	lastActivityRe := regexp.MustCompile(`Dernière visite le ([0-9]{1,2} [a-zéû]+ [0-9]{4})|Last seen ([A-Za-z]+ [0-9]{1,2}, [0-9]{4})`)
	if m := lastActivityRe.FindStringSubmatch(content); len(m) > 1 {
		lastActivity := ""
		if m[1] != "" {
			lastActivity = m[1]
		} else if m[2] != "" {
			lastActivity = m[2]
		}
		if lastActivity != "" {
			p.Fields["last_activity"] = lastActivity
		}
	}

	// Extract forum message count
	messagesRe := regexp.MustCompile(`(\d+)\s+messages? de forum`)
	if m := messagesRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["forum_messages"] = m[1]
	}

	// Extract forum topic count
	topicsRe := regexp.MustCompile(`(\d+)\s+sujets? de forum`)
	if m := topicsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["forum_topics"] = m[1]
	}

	// Extract published content count
	contentRe := regexp.MustCompile(`(\d+)\s+contenus? publiés?`)
	if m := contentRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["published_content"] = m[1]
	}

	// Extract comment count
	commentsRe := regexp.MustCompile(`(\d+)\s+commentaires? publiés?`)
	if m := commentsRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["comments"] = m[1]
	}

	// Extract subscriber count
	subscribersRe := regexp.MustCompile(`(\d+)\s+abonnés?`)
	if m := subscribersRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["subscribers"] = m[1]
	}

	// Extract bio from meta description or profile section
	bioRe := regexp.MustCompile(`<meta[^>]+name="description"[^>]+content="([^"]+)"`)
	if m := bioRe.FindStringSubmatch(content); len(m) > 1 {
		bio := strings.TrimSpace(m[1])
		if !strings.Contains(bio, "Zeste de Savoir") {
			p.Bio = bio
		}
	}

	// Extract email from PGP key or contact section
	emailRe := regexp.MustCompile(`([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})`)
	if m := emailRe.FindStringSubmatch(content); len(m) > 1 {
		p.Fields["email"] = m[1]
	}

	// Extract social links
	p.SocialLinks = htmlutil.SocialLinks(content)

	// Extract recent forum topics and posts
	p.Posts = extractPosts(content, username)

	return p, nil
}

// extractPosts extracts recent forum topics and published content.
func extractPosts(content, username string) []profile.Post {
	var posts []profile.Post

	// Look for forum topic links
	topicRe := regexp.MustCompile(`<a[^>]+href="(/forums/sujet/[^"]+)"[^>]*>([^<]+)</a>`)
	matches := topicRe.FindAllStringSubmatch(content, 20)

	seen := make(map[string]bool)
	for _, m := range matches {
		if len(m) <= 2 {
			continue
		}
		url := "https://zestedesavoir.com" + m[1]
		title := strings.TrimSpace(m[2])

		if len(title) < 5 || seen[url] {
			continue
		}
		seen[url] = true

		posts = append(posts, profile.Post{
			Type:  profile.PostTypeComment,
			Title: title,
			URL:   url,
		})

		if len(posts) >= 10 {
			break
		}
	}

	// Also look for published tutorials/articles
	if len(posts) < 10 {
		tutorialRe := regexp.MustCompile(`<a[^>]+href="(/tutoriels/[^"]+)"[^>]*>([^<]+)</a>`)
		tutorialMatches := tutorialRe.FindAllStringSubmatch(content, 20)

		for _, m := range tutorialMatches {
			if len(m) <= 2 || len(posts) >= 10 {
				break
			}
			url := "https://zestedesavoir.com" + m[1]
			title := strings.TrimSpace(m[2])

			if len(title) < 5 || seen[url] {
				continue
			}
			seen[url] = true

			posts = append(posts, profile.Post{
				Type:  profile.PostTypeArticle,
				Title: title,
				URL:   url,
			})
		}
	}

	return posts
}

// extractUsername extracts username from Zeste de Savoir URL.
func extractUsername(urlStr string) string {
	// Handle zestedesavoir.com/@username
	if idx := strings.Index(urlStr, "/@"); idx != -1 {
		username := urlStr[idx+2:]
		username = strings.Split(username, "/")[0]
		username = strings.Split(username, "?")[0]
		return strings.TrimSpace(username)
	}
	return ""
}
