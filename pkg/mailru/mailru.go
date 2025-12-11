// Package mailru fetches Mail.ru (My World) profile data.
//
// This package supports:
//   - Mail.ru email addresses: user@mail.ru, user@inbox.ru, user@list.ru, user@bk.ru
//   - My World profile URLs: my.mail.ru/mail/username
//
// Mail.ru profiles are public and include avatar, name, and basic info.
package mailru

import (
	"context"
	"errors"
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

const platform = "mailru"

// emailRegex matches Mail.ru email addresses.
var emailRegex = regexp.MustCompile(`(?i)^(?:mailto:)?([a-zA-Z0-9._%+-]+)@(mail\.ru|inbox\.ru|list\.ru|bk\.ru)$`)

// profileURLRegex matches My World profile URLs.
var profileURLRegex = regexp.MustCompile(`(?i)my\.mail\.ru/(mail|inbox|list|bk)/([a-zA-Z0-9._-]+)`)

// avatarRegex extracts avatar URL from page content.
var avatarRegex = regexp.MustCompile(`(?i)(https?://[a-z0-9-]+\.foto\.mail\.ru/[^"'\s]+_avatar\d+[^"'\s]*)`)

// Match returns true if the input is a Mail.ru email or My World profile URL.
func Match(input string) bool {
	input = strings.TrimSpace(input)
	return emailRegex.MatchString(input) || profileURLRegex.MatchString(input)
}

// AuthRequired returns false because Mail.ru profiles are public.
func AuthRequired() bool { return false }

// Client handles Mail.ru requests.
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

// New creates a Mail.ru client.
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

// Fetch retrieves Mail.ru profile data.
func (c *Client) Fetch(ctx context.Context, input string) (*profile.Profile, error) {
	input = strings.TrimSpace(input)

	var username, domain, email string

	// Parse the input
	if matches := emailRegex.FindStringSubmatch(input); len(matches) > 2 {
		username = strings.ToLower(matches[1])
		domain = strings.ToLower(matches[2])
		email = username + "@" + domain
	} else if matches := profileURLRegex.FindStringSubmatch(input); len(matches) > 2 {
		domain = strings.ToLower(matches[1]) + ".ru"
		if matches[1] == "mail" {
			domain = "mail.ru"
		}
		username = matches[2]
		email = username + "@" + domain
	} else {
		return nil, fmt.Errorf("could not parse input: %s", input)
	}

	// Determine the domain prefix for the URL
	domainPrefix := "mail"
	switch domain {
	case "inbox.ru":
		domainPrefix = "inbox"
	case "list.ru":
		domainPrefix = "list"
	case "bk.ru":
		domainPrefix = "bk"
	default:
		// mail.ru uses "mail" prefix, which is already set
	}

	profileURL := fmt.Sprintf("https://my.mail.ru/%s/%s/", domainPrefix, username)

	c.logger.InfoContext(ctx, "fetching mailru profile", "email", email, "url", profileURL)

	prof := &profile.Profile{
		Platform: platform,
		URL:      profileURL,
		Username: username,
		Fields:   make(map[string]string),
	}
	prof.Fields["email"] = email

	// Fetch the profile page
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, profileURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")

	body, err := c.doRequest(ctx, req)
	if err != nil {
		prof.Error = fmt.Sprintf("fetch failed: %v", err)
		return prof, nil
	}

	// Parse the HTML response
	c.parseHTML(string(body), prof)

	// Construct avatar URL directly (predictable pattern)
	prof.AvatarURL = fmt.Sprintf("https://avt-15.foto.mail.ru/%s/%s/_avatar180", domainPrefix, username)

	return prof, nil
}

func (c *Client) doRequest(ctx context.Context, req *http.Request) ([]byte, error) {
	if c.cache != nil {
		return httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // defer closes body

	if resp.StatusCode == http.StatusNotFound {
		return nil, errors.New("profile not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (*Client) parseHTML(content string, prof *profile.Profile) {
	// Extract name from title: "Name - Age on My World@Mail.Ru"
	title := htmlutil.Title(content)
	if title != "" {
		// Remove " on My World@Mail.Ru" suffix
		if idx := strings.Index(title, " on My World"); idx > 0 {
			title = title[:idx]
		}
		// The format is typically "Name - Age" or just "Name"
		if idx := strings.LastIndex(title, " - "); idx > 0 {
			prof.Name = strings.TrimSpace(title[:idx])
			// Age info could be extracted here if needed
		} else {
			prof.Name = strings.TrimSpace(title)
		}
	}

	// Extract description/bio
	prof.Bio = htmlutil.Description(content)

	// Try to find a higher-res avatar in the page
	if matches := avatarRegex.FindStringSubmatch(content); len(matches) > 1 {
		prof.AvatarURL = matches[1]
	}

	// Extract social links
	prof.SocialLinks = htmlutil.SocialLinks(content)
}
