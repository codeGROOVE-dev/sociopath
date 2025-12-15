// Package keybase fetches Keybase profile data.
package keybase

import (
	"context"
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

const platform = "keybase"

// platformInfo implements profile.Platform for Keybase.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var usernamePattern = regexp.MustCompile(`(?i)keybase\.io/([a-zA-Z0-9_]+)`)

// Match returns true if the URL is a Keybase profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	return strings.Contains(lower, "keybase.io/") && usernamePattern.MatchString(urlStr)
}

// AuthRequired returns false because Keybase profiles are public.
func AuthRequired() bool { return false }

// Client handles Keybase requests.
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

// New creates a Keybase client.
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

// apiResponse represents the Keybase API response.
//
//nolint:govet // field alignment not critical for JSON parsing
type apiResponse struct {
	Status struct {
		Code int    `json:"code"`
		Name string `json:"name"`
	} `json:"status"`
	Them *userData `json:"them"`
}

//nolint:govet // field alignment not critical for JSON parsing
type userData struct {
	ID       string `json:"id"`
	Basics   basics `json:"basics"`
	Profile  prof   `json:"profile"`
	Pictures pics   `json:"pictures"`
	Proofs   proofs `json:"proofs_summary"`
}

type basics struct {
	Username      string `json:"username"`
	UsernameCased string `json:"username_cased"`
}

type prof struct {
	FullName string `json:"full_name"`
	Location string `json:"location"`
	Bio      string `json:"bio"`
}

type pics struct {
	Primary struct {
		URL string `json:"url"`
	} `json:"primary"`
}

type proofs struct {
	ByPresentationGroup map[string][]proof `json:"by_presentation_group"`
}

//nolint:govet // field alignment not critical for JSON parsing
type proof struct {
	ProofType  string `json:"proof_type"`
	Nametag    string `json:"nametag"`
	State      int    `json:"state"`
	ServiceURL string `json:"service_url"`
}

// Fetch retrieves a Keybase profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	username := extractUsername(urlStr)
	if username == "" {
		return nil, fmt.Errorf("could not extract username from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching keybase profile", "url", urlStr, "username", username)

	apiURL := fmt.Sprintf("https://keybase.io/_/api/1.0/user/lookup.json?username=%s&fields=profile,pictures,proofs_summary", username)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse keybase response: %w", err)
	}

	if resp.Status.Code != 0 || resp.Them == nil {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(resp.Them, urlStr), nil
}

func parseProfile(data *userData, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: data.Basics.UsernameCased,
		Name:     data.Profile.FullName,
		Bio:      data.Profile.Bio,
		Fields:   make(map[string]string),
	}

	if p.Username == "" {
		p.Username = data.Basics.Username
	}

	if data.Profile.Location != "" {
		p.Location = data.Profile.Location
	}

	if data.Pictures.Primary.URL != "" {
		p.AvatarURL = data.Pictures.Primary.URL
	}

	// Extract social links from verified proofs
	for groupName, proofList := range data.Proofs.ByPresentationGroup {
		for _, proof := range proofList {
			// Only include verified proofs (state == 1)
			if proof.State != 1 || proof.ServiceURL == "" {
				continue
			}

			// Add to social links
			p.SocialLinks = append(p.SocialLinks, proof.ServiceURL)

			// Also store in fields by platform
			switch proof.ProofType {
			case "twitter":
				p.Fields["twitter"] = proof.ServiceURL
			case "github":
				p.Fields["github"] = proof.ServiceURL
			case "reddit":
				p.Fields["reddit"] = proof.ServiceURL
			case "hackernews":
				p.Fields["hackernews"] = proof.Nametag
			case "generic_web_site":
				if strings.HasPrefix(groupName, "web:") {
					p.Fields["website"] = proof.ServiceURL
					p.Website = proof.ServiceURL
				}
			default:
				// Other proof types are added to SocialLinks only
			}
		}
	}

	if p.Name == "" {
		p.Name = p.Username
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
