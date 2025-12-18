// Package whatsapp extracts phone numbers from WhatsApp URLs.
package whatsapp

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "whatsapp"

// platformInfo implements profile.Platform for WhatsApp.
type platformInfo struct{}

func (platformInfo) Name() string               { return platform }
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeSocial }
func (platformInfo) Match(url string) bool      { return Match(url) }
func (platformInfo) AuthRequired() bool         { return false }

func init() { profile.Register(platformInfo{}) }

// URL patterns for WhatsApp links.
var (
	waMePattern     = regexp.MustCompile(`(?i)wa\.me/\+?(\d{7,15})`)
	phoneQueryParam = regexp.MustCompile(`phone=\+?(\d{7,15})`)
)

// Match returns true if the URL is a WhatsApp link with a phone number.
func Match(urlStr string) bool {
	if waMePattern.MatchString(urlStr) {
		return true
	}
	if strings.Contains(strings.ToLower(urlStr), "api.whatsapp.com/send") && phoneQueryParam.MatchString(urlStr) {
		return true
	}
	return false
}

// Client handles WhatsApp URL parsing. No HTTP requests needed - just URL parsing.
type Client struct {
	logger *slog.Logger
}

// Option configures a Client.
type Option func(*Client)

// WithHTTPCache is a no-op for WhatsApp (no HTTP requests needed).
func WithHTTPCache(_ httpcache.Cacher) Option { return func(*Client) {} }

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) { c.logger = logger }
}

// New creates a WhatsApp client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	c := &Client{logger: slog.Default()}
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

// Fetch extracts phone number from a WhatsApp URL.
func (c *Client) Fetch(ctx context.Context, urlStr string) (*profile.Profile, error) {
	phone := extractPhone(urlStr)
	if phone == "" {
		return nil, fmt.Errorf("could not extract phone number from URL: %s", urlStr)
	}

	c.logger.InfoContext(ctx, "parsing whatsapp link", "url", urlStr, "phone", phone)

	p := &profile.Profile{
		Platform:    platform,
		URL:         fmt.Sprintf("https://wa.me/%s", phone),
		Username:    phone,
		DisplayName: formatPhone(phone),
		Fields:      make(map[string]string),
	}
	p.Fields["phone"] = phone

	return p, nil
}

// extractPhone pulls the phone number from various WhatsApp URL formats.
func extractPhone(url string) string {
	if m := waMePattern.FindStringSubmatch(url); len(m) > 1 {
		return m[1]
	}
	if m := phoneQueryParam.FindStringSubmatch(url); len(m) > 1 {
		return m[1]
	}
	return ""
}

// formatPhone formats a phone number with country code and spacing.
// For example, 61488999087 becomes +61 488 999 087.
func formatPhone(phone string) string {
	if len(phone) < 7 {
		return "+" + phone
	}

	// Detect country code length based on known patterns.
	var cc, num string
	switch {
	case strings.HasPrefix(phone, "1") && len(phone) == 11:
		cc, num = phone[:1], phone[1:] // North America
	case strings.HasPrefix(phone, "61") && len(phone) == 11:
		cc, num = phone[:2], phone[2:] // Australia
	case strings.HasPrefix(phone, "44") && len(phone) >= 11:
		cc, num = phone[:2], phone[2:] // UK
	case strings.HasPrefix(phone, "49") && len(phone) >= 11:
		cc, num = phone[:2], phone[2:] // Germany
	case strings.HasPrefix(phone, "33") && len(phone) == 11:
		cc, num = phone[:2], phone[2:] // France
	case strings.HasPrefix(phone, "86") && len(phone) == 13:
		cc, num = phone[:2], phone[2:] // China
	case strings.HasPrefix(phone, "91") && len(phone) == 12:
		cc, num = phone[:2], phone[2:] // India
	default:
		if len(phone) < 10 {
			return "+" + phone
		}
		cc, num = phone[:2], phone[2:]
	}

	var b strings.Builder
	b.WriteString("+")
	b.WriteString(cc)
	for i, r := range num {
		if i%3 == 0 {
			b.WriteString(" ")
		}
		b.WriteRune(r)
	}
	return b.String()
}
