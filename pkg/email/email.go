// Package email handles generic email addresses from major providers.
//
// This package supports major email providers like Outlook, ProtonMail, Yahoo,
// iCloud, AOL, and others. It extracts usernames for cross-platform guessing.
//
// For Gmail addresses, use the google package which has GAIA ID resolution.
// For Mail.ru addresses, use the mailru package which has profile fetching.
package email

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "email"

// platformInfo implements profile.Platform for generic email.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return AuthRequired() }

func init() { profile.Register(platformInfo{}) }

var (
	// emailRegex matches email addresses with optional mailto: prefix.
	// Excludes gmail.com (handled by google package) and mail.ru domains (handled by mailru package).
	emailRegex = regexp.MustCompile(`(?i)^(?:mailto:)?([a-zA-Z0-9._%+-]+)@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})$`)

	// Major providers supported by this package (excluding Gmail and Mail.ru).
	supportedProviders = map[string]bool{
		"outlook.com": true, "hotmail.com": true, "live.com": true, "msn.com": true, // Microsoft
		"proton.me": true, "protonmail.com": true, "pm.me": true, // ProtonMail
		"yahoo.com": true, "ymail.com": true, "rocketmail.com": true, // Yahoo
		"icloud.com": true, "me.com": true, "mac.com": true, // Apple
		"aol.com":  true,                       // AOL
		"zoho.com": true, "zohomail.com": true, // Zoho
		"gmx.com": true, "gmx.net": true, // GMX
		"mail.com":     true,                      // Mail.com
		"fastmail.com": true, "fastmail.fm": true, // FastMail
		"tutanota.com": true, "tutanota.de": true, "tuta.io": true, // Tutanota
	}
)

// Match returns true if the input is a supported email address.
// Gmail and Mail.ru domains are excluded as they have dedicated packages.
func Match(input string) bool {
	input = strings.TrimSpace(input)
	matches := emailRegex.FindStringSubmatch(input)
	if len(matches) < 3 {
		return false
	}

	domain := strings.ToLower(matches[2])

	// Exclude Gmail (handled by google package)
	if domain == "gmail.com" {
		return false
	}

	// Exclude Mail.ru domains (handled by mailru package)
	if domain == "mail.ru" || domain == "inbox.ru" || domain == "list.ru" || domain == "bk.ru" {
		return false
	}

	// Check if it's a supported major provider
	return supportedProviders[domain]
}

// AuthRequired returns false because we don't fetch any external data.
func AuthRequired() bool { return false }

// Client handles email address extraction.
type Client struct{}

// New creates an email client.
func New(_ context.Context, _ ...Option) (*Client, error) {
	return &Client{}, nil
}

// Option configures the email client.
type Option func(*config)

type config struct {
	cache  any // Not used but kept for consistency
	logger any // Not used but kept for consistency
}

// WithHTTPCache is a stub for consistency with other packages.
// Email parsing doesn't require HTTP caching.
func WithHTTPCache(cache any) Option {
	return func(c *config) {
		c.cache = cache
	}
}

// WithLogger is a stub for consistency with other packages.
// Email parsing doesn't require logging.
func WithLogger(logger any) Option {
	return func(c *config) {
		c.logger = logger
	}
}

// Fetch extracts username and email from a mailto: URL.
func (*Client) Fetch(_ context.Context, input string) (*profile.Profile, error) {
	input = strings.TrimSpace(input)

	matches := emailRegex.FindStringSubmatch(input)
	if len(matches) < 3 {
		return nil, fmt.Errorf("invalid email format: %s", input)
	}

	username := matches[1]
	domain := strings.ToLower(matches[2])
	email := username + "@" + domain

	// Double-check we should handle this domain
	if !Match(input) {
		return nil, fmt.Errorf("email domain not supported: %s", domain)
	}

	prof := &profile.Profile{
		Platform: platform,
		Username: username,
		URL:      "mailto:" + email,
		Fields: map[string]string{
			"email":  email,
			"domain": domain,
		},
	}

	return prof, nil
}
