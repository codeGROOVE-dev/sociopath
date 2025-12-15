// Package gravatar fetches Gravatar profile data from email addresses.
//
// Gravatar uses SHA256 hashes of email addresses to look up profiles.
// This package supports any email address - if a Gravatar profile exists,
// it returns the profile photo, display name, and linked accounts.
package gravatar

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "gravatar"

// platformInfo implements profile.Platform for Gravatar.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// emailRegex matches email addresses with optional mailto: prefix.
var emailRegex = regexp.MustCompile(`(?i)^(?:mailto:)?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$`)

// gravatarURLRegex matches Gravatar profile URLs.
var gravatarURLRegex = regexp.MustCompile(`(?i)gravatar\.com/([a-f0-9]{64}|[a-zA-Z0-9_-]+)`)

// Match returns true if the input is an email address or Gravatar URL.
// Note: This matches ANY email address, not just specific domains.
func Match(input string) bool {
	input = strings.TrimSpace(input)
	return emailRegex.MatchString(input) || gravatarURLRegex.MatchString(input)
}

// AuthRequired returns false because Gravatar lookups are public.
func AuthRequired() bool { return false }

// Client handles Gravatar requests.
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

// New creates a Gravatar client.
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

// Fetch retrieves Gravatar profile data for an email address.
func (c *Client) Fetch(ctx context.Context, input string) (*profile.Profile, error) {
	input = strings.TrimSpace(input)

	var email, hash string

	// Parse the input
	if matches := emailRegex.FindStringSubmatch(input); len(matches) > 1 {
		email = strings.ToLower(matches[1])
		hash = hashEmail(email)
	} else if matches := gravatarURLRegex.FindStringSubmatch(input); len(matches) > 1 {
		hash = matches[1]
	} else {
		return nil, fmt.Errorf("could not parse input: %s", input)
	}

	c.logger.InfoContext(ctx, "fetching gravatar profile", "email", email, "hash", hash)

	prof := &profile.Profile{
		Platform: platform,
		Fields:   make(map[string]string),
	}

	if email != "" {
		prof.Fields["email"] = email
	}
	prof.Fields["hash"] = hash

	// Fetch profile from Gravatar JSON API
	apiURL := fmt.Sprintf("https://gravatar.com/%s.json", hash)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("User-Agent", "sociopath/1.0")

	body, fetchErr := c.doRequest(ctx, req)
	if fetchErr != nil {
		// 404 means no Gravatar profile exists - return minimal profile with identicon
		prof.URL = fmt.Sprintf("https://gravatar.com/avatar/%s", hash)
		prof.AvatarURL = fmt.Sprintf("https://gravatar.com/avatar/%s?d=identicon", hash)
		return prof, nil //nolint:nilerr // 404/not-found is valid - we return a minimal profile
	}

	// Parse JSON response
	if err := c.parseResponse(body, prof); err != nil {
		c.logger.WarnContext(ctx, "failed to parse gravatar response", "error", err)
		prof.Error = fmt.Sprintf("parse failed: %v", err)
	}

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
		return nil, errors.New("not found")
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// gravatarResponse represents the Gravatar JSON API response.
type gravatarResponse struct {
	Entry []gravatarEntry `json:"entry"`
}

type gravatarEntry struct {
	Hash              string          `json:"hash"`
	RequestHash       string          `json:"requestHash"`
	ProfileURL        string          `json:"profileUrl"`
	PreferredUsername string          `json:"preferredUsername"`
	ThumbnailURL      string          `json:"thumbnailUrl"`
	DisplayName       string          `json:"displayName"`
	Name              *gravatarName   `json:"name"`
	AboutMe           string          `json:"aboutMe"`
	CurrentLocation   string          `json:"currentLocation"`
	Photos            []gravatarPhoto `json:"photos"`
	Emails            []gravatarEmail `json:"emails"`
	URLs              []gravatarURL   `json:"urls"`
	Accounts          []gravatarAcct  `json:"accounts"`
}

type gravatarName struct {
	Formatted  string `json:"formatted"`
	GivenName  string `json:"givenName"`
	FamilyName string `json:"familyName"`
}

type gravatarPhoto struct {
	Value string `json:"value"`
	Type  string `json:"type"`
}

type gravatarEmail struct {
	Primary any    `json:"primary"` // Can be bool or string "true"/"false"
	Value   string `json:"value"`
}

type gravatarURL struct {
	Value string `json:"value"`
	Title string `json:"title"`
}

type gravatarAcct struct {
	Domain    string `json:"domain"`
	Username  string `json:"username"`
	Display   string `json:"display"`
	URL       string `json:"url"`
	Shortname string `json:"shortname"`
}

func (*Client) parseResponse(data []byte, prof *profile.Profile) error {
	var resp gravatarResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return err
	}

	if len(resp.Entry) == 0 {
		return errors.New("no entries in response")
	}

	entry := resp.Entry[0]

	prof.URL = entry.ProfileURL
	prof.Username = entry.PreferredUsername

	// Set display name
	if entry.DisplayName != "" {
		prof.Name = entry.DisplayName
	} else if entry.Name != nil && entry.Name.Formatted != "" {
		prof.Name = entry.Name.Formatted
	}

	// Set avatar
	if entry.ThumbnailURL != "" {
		prof.AvatarURL = entry.ThumbnailURL
	} else if len(entry.Photos) > 0 {
		prof.AvatarURL = entry.Photos[0].Value
	}

	// Set bio and location
	prof.Bio = entry.AboutMe
	prof.Location = entry.CurrentLocation

	// Add primary email if available
	for _, e := range entry.Emails {
		if isPrimary(e.Primary) {
			prof.Fields["primary_email"] = e.Value
			break
		}
	}

	// Add URLs as social links
	for _, u := range entry.URLs {
		prof.SocialLinks = append(prof.SocialLinks, u.Value)
	}

	// Add linked accounts as social links
	for _, a := range entry.Accounts {
		if a.URL != "" {
			prof.SocialLinks = append(prof.SocialLinks, a.URL)
		}
	}

	return nil
}

// isPrimary checks if a primary field value is truthy (handles bool or string).
func isPrimary(v any) bool {
	switch val := v.(type) {
	case bool:
		return val
	case string:
		return val == "true" || val == "1"
	default:
		return false
	}
}

// hashEmail returns the SHA256 hash of an email address (lowercased, trimmed).
func hashEmail(email string) string {
	email = strings.ToLower(strings.TrimSpace(email))
	h := sha256.Sum256([]byte(email))
	return hex.EncodeToString(h[:])
}
