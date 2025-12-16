// Package orcid fetches ORCID researcher profile data.
package orcid

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

const platform = "orcid"

// platformInfo implements profile.Platform for ORCID.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

// ORCID pattern: 0000-0000-0000-0000 (16 digits with hyphens, last char can be X).
var orcidPattern = regexp.MustCompile(`(?i)orcid\.org/(\d{4}-\d{4}-\d{4}-\d{3}[\dX])`)

// Match returns true if the URL is an ORCID profile URL.
func Match(urlStr string) bool {
	lower := strings.ToLower(urlStr)
	if !strings.Contains(lower, "orcid.org/") {
		return false
	}
	return orcidPattern.MatchString(urlStr)
}

// AuthRequired returns false because ORCID profiles are public.
func AuthRequired() bool { return false }

// Client handles ORCID requests.
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

// New creates an ORCID client.
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

// apiResponse represents the ORCID public record response.
type apiResponse struct {
	DisplayName string `json:"displayName"`
	Names       struct {
		GivenNames struct {
			Value string `json:"value"`
		} `json:"givenNames"`
		FamilyName struct {
			Value string `json:"value"`
		} `json:"familyName"`
		CreditName struct {
			Value string `json:"value"`
		} `json:"creditName"`
	} `json:"names"`
	Biography struct {
		Biography struct {
			Value string `json:"value"`
		} `json:"biography"`
	} `json:"biography"`
	Countries struct {
		Addresses []struct {
			CountryName string `json:"countryName"`
		} `json:"addresses"`
	} `json:"countries"`
	Website struct {
		Websites []struct {
			URL struct {
				Value string `json:"value"`
			} `json:"url"`
			URLName string `json:"urlName"`
		} `json:"websites"`
	} `json:"website"`
	Keyword struct {
		Keywords []struct {
			Content string `json:"content"`
		} `json:"keywords"`
	} `json:"keyword"`
}

// Fetch retrieves an ORCID profile.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	orcidID := extractORCID(urlStr)
	if orcidID == "" {
		return nil, fmt.Errorf("could not extract ORCID from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "fetching orcid profile", "url", urlStr, "orcid", orcidID)

	apiURL := fmt.Sprintf("https://orcid.org/%s/public-record.json", orcidID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:146.0) Gecko/20100101 Firefox/146.0")
	req.Header.Set("Accept", "application/json")

	body, err := httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	if err != nil {
		return nil, err
	}

	var resp apiResponse
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse orcid response: %w", err)
	}

	if resp.DisplayName == "" && resp.Names.GivenNames.Value == "" {
		return nil, profile.ErrProfileNotFound
	}

	return parseProfile(&resp, orcidID, urlStr), nil
}

func parseProfile(data *apiResponse, orcidID, url string) *profile.Profile {
	p := &profile.Profile{
		Platform: platform,
		URL:      url,
		Username: orcidID,
		Fields:   make(map[string]string),
	}

	// Name - prefer credit name, then display name, then constructed name
	switch {
	case data.Names.CreditName.Value != "":
		p.DisplayName = data.Names.CreditName.Value
	case data.DisplayName != "":
		p.DisplayName = data.DisplayName
	default:
		p.DisplayName = strings.TrimSpace(data.Names.GivenNames.Value + " " + data.Names.FamilyName.Value)
	}

	// Bio
	if data.Biography.Biography.Value != "" {
		p.Bio = data.Biography.Biography.Value
	}

	// Location (country)
	if len(data.Countries.Addresses) > 0 {
		p.Location = data.Countries.Addresses[0].CountryName
	}

	// Keywords as interests
	if len(data.Keyword.Keywords) > 0 {
		var keywords []string
		for _, kw := range data.Keyword.Keywords {
			if kw.Content != "" {
				keywords = append(keywords, kw.Content)
			}
		}
		if len(keywords) > 0 {
			p.Fields["keywords"] = strings.Join(keywords, ", ")
		}
	}

	// Websites - extract social links
	for _, site := range data.Website.Websites {
		if site.URL.Value == "" {
			continue
		}

		url := site.URL.Value
		nameLower := strings.ToLower(site.URLName)

		// Categorize by name or URL pattern
		switch {
		case strings.Contains(nameLower, "linkedin") || strings.Contains(url, "linkedin.com"):
			p.Fields["linkedin"] = url
			p.SocialLinks = append(p.SocialLinks, url)
		case strings.Contains(nameLower, "github") || strings.Contains(url, "github.com"):
			p.Fields["github"] = url
			p.SocialLinks = append(p.SocialLinks, url)
		case strings.Contains(nameLower, "twitter") || strings.Contains(url, "twitter.com") || strings.Contains(url, "x.com"):
			p.Fields["twitter"] = url
			p.SocialLinks = append(p.SocialLinks, url)
		case strings.Contains(nameLower, "researchgate") || strings.Contains(url, "researchgate.net"):
			p.Fields["researchgate"] = url
			p.SocialLinks = append(p.SocialLinks, url)
		case strings.Contains(nameLower, "google scholar") || strings.Contains(url, "scholar.google"):
			p.Fields["google_scholar"] = url
			p.SocialLinks = append(p.SocialLinks, url)
		default:
			// Add as generic social link
			p.SocialLinks = append(p.SocialLinks, url)
		}
	}

	return p
}

func extractORCID(urlStr string) string {
	matches := orcidPattern.FindStringSubmatch(urlStr)
	if len(matches) > 1 {
		return matches[1]
	}
	return ""
}
