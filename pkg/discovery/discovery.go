// Package discovery provides identity discovery via DNS records, well-known endpoints, and APIs.
// It discovers linked profiles from personal domains through various verification methods.
package discovery

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
)

// Result represents a discovered identity.
type Result struct {
	Platform string // e.g., "keybase", "bluesky", "nostr", "fediverse"
	URL      string // Profile URL
	Username string // Username if available
}

// Cacher allows external cache implementations for sharing across packages.
type Cacher interface {
	GetSet(ctx context.Context, key string, fetch func(context.Context) ([]byte, error), ttl ...time.Duration) ([]byte, error)
	TTL() time.Duration
}

// Discoverer finds linked identities for a domain.
type Discoverer struct {
	cache  Cacher
	client *http.Client
	logger *slog.Logger
}

// New creates a new Discoverer.
func New(cache Cacher, logger *slog.Logger) *Discoverer {
	if logger == nil {
		logger = slog.Default()
	}
	if cache == nil {
		cache = httpcache.NewNull()
	}
	return &Discoverer{
		cache:  cache,
		client: &http.Client{Timeout: 5 * time.Second},
		logger: logger,
	}
}

// DiscoverAll runs all discovery methods for a domain and returns found identities.
func (d *Discoverer) DiscoverAll(ctx context.Context, domain string) []Result {
	if domain == "" || IsKnownSocialDomain(domain) {
		return nil
	}

	var results []Result

	if r := d.LookupKeybase(ctx, domain); r != nil {
		results = append(results, *r)
	}
	if r := d.LookupBluesky(ctx, domain); r != nil {
		results = append(results, *r)
	}
	if r := d.LookupNostr(ctx, domain); r != nil {
		results = append(results, *r)
	}
	if r := d.LookupMatrix(ctx, domain); r != nil {
		results = append(results, *r)
	}

	return results
}

// LookupWebFinger queries WebFinger to discover Fediverse profiles from email addresses.
func (d *Discoverer) LookupWebFinger(ctx context.Context, email string) *Result {
	parts := strings.SplitN(email, "@", 2)
	if len(parts) != 2 {
		return nil
	}
	localPart, domain := parts[0], parts[1]

	if commonEmailProviders[strings.ToLower(domain)] || IsKnownSocialDomain(domain) {
		return nil
	}

	webfingerURL := fmt.Sprintf("https://%s/.well-known/webfinger?resource=acct:%s@%s",
		domain, url.QueryEscape(localPart), domain)

	body, err := d.fetch(ctx, webfingerURL)
	if err != nil {
		d.logger.DebugContext(ctx, "webfinger lookup failed", "email", email, "error", err)
		return nil
	}

	var result struct {
		Links []struct {
			Rel  string `json:"rel"`
			Href string `json:"href"`
		} `json:"links"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		d.logger.DebugContext(ctx, "webfinger parse failed", "email", email, "error", err)
		return nil
	}

	// WebFinger spec uses http URI as identifier (not an actual URL)
	const profilePageRel = "http://webfinger.net/rel/profile-page" //nolint:revive // WebFinger spec uses http URI
	for _, link := range result.Links {
		if link.Rel == profilePageRel && link.Href != "" {
			d.logger.DebugContext(ctx, "fediverse profile found", "email", email, "url", link.Href)
			return &Result{Platform: "fediverse", URL: link.Href}
		}
	}

	return nil
}

// LookupKeybase queries the Keybase API to find a user who has verified a domain.
func (d *Discoverer) LookupKeybase(ctx context.Context, domain string) *Result {
	apiURL := fmt.Sprintf("https://keybase.io/_/api/1.0/user/lookup.json?domain=%s", url.QueryEscape(domain))

	body, err := d.fetch(ctx, apiURL)
	if err != nil {
		d.logger.DebugContext(ctx, "keybase lookup failed", "domain", domain, "error", err)
		return nil
	}

	var result struct {
		Them []struct {
			Basics struct {
				Username string `json:"username"`
			} `json:"basics"`
		} `json:"them"`
		Status struct {
			Name string `json:"name"`
			Code int    `json:"code"`
		} `json:"status"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		d.logger.DebugContext(ctx, "keybase parse failed", "domain", domain, "error", err)
		return nil
	}

	if result.Status.Code != 0 || len(result.Them) == 0 {
		return nil
	}

	username := result.Them[0].Basics.Username
	if username == "" {
		return nil
	}

	d.logger.DebugContext(ctx, "keybase user found", "domain", domain, "username", username)
	return &Result{
		Platform: "keybase",
		URL:      "https://keybase.io/" + username,
		Username: username,
	}
}

// LookupBluesky checks DNS TXT records for AT Protocol (Bluesky) verification.
func (d *Discoverer) LookupBluesky(ctx context.Context, domain string) *Result {
	dnsKey := "_atproto." + domain
	cacheKey := "dns:" + dnsKey

	data, err := d.cache.GetSet(ctx, cacheKey, func(ctx context.Context) ([]byte, error) {
		records, err := net.DefaultResolver.LookupTXT(ctx, dnsKey)
		if err != nil {
			return nil, err
		}
		return []byte(strings.Join(records, "\n")), nil
	}, d.cache.TTL())
	if err != nil {
		d.logger.DebugContext(ctx, "bluesky DNS lookup failed", "domain", domain, "error", err)
		return nil
	}

	for _, txt := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(txt, "did=") {
			d.logger.DebugContext(ctx, "bluesky handle found", "domain", domain, "did", txt)
			return &Result{
				Platform: "bluesky",
				URL:      "https://bsky.app/profile/" + domain,
				Username: domain,
			}
		}
	}

	return nil
}

// LookupNostr checks the NIP-05 well-known endpoint for Nostr verification.
func (d *Discoverer) LookupNostr(ctx context.Context, domain string) *Result {
	nip05URL := fmt.Sprintf("https://%s/.well-known/nostr.json?name=_", domain)

	body, err := d.fetch(ctx, nip05URL)
	if err != nil {
		d.logger.DebugContext(ctx, "nostr NIP-05 lookup failed", "domain", domain, "error", err)
		return nil
	}

	var result struct {
		Names map[string]string `json:"names"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		d.logger.DebugContext(ctx, "nostr NIP-05 parse failed", "domain", domain, "error", err)
		return nil
	}

	pubkey := result.Names["_"]
	if pubkey == "" || !isValidHexPubkey(pubkey) {
		return nil
	}

	d.logger.DebugContext(ctx, "nostr identity found", "domain", domain, "pubkey", pubkey)
	return &Result{
		Platform: "nostr",
		URL:      "https://njump.me/" + pubkey,
		Username: pubkey,
	}
}

// LookupMatrix checks the Matrix well-known endpoint to see if the domain hosts a homeserver.
func (d *Discoverer) LookupMatrix(ctx context.Context, domain string) *Result {
	matrixURL := fmt.Sprintf("https://%s/.well-known/matrix/server", domain)

	body, err := d.fetch(ctx, matrixURL)
	if err != nil {
		d.logger.DebugContext(ctx, "matrix well-known lookup failed", "domain", domain, "error", err)
		return nil
	}

	var result struct {
		Server string `json:"m.server"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		d.logger.DebugContext(ctx, "matrix well-known parse failed", "domain", domain, "error", err)
		return nil
	}

	if result.Server == "" {
		return nil
	}

	d.logger.DebugContext(ctx, "matrix homeserver found", "domain", domain, "server", result.Server)
	return &Result{
		Platform: "matrix",
		URL:      "https://matrix.to/#/@:" + domain,
		Username: "@:" + domain,
	}
}

// fetch performs an HTTP GET request and returns the response body.
func (d *Discoverer) fetch(ctx context.Context, urlStr string) ([]byte, error) {
	doFetch := func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, http.NoBody)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "sociopath/1.0")

		resp, err := d.client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close() //nolint:errcheck // response body must be closed

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("status %d", resp.StatusCode)
		}

		return io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	}

	cacheKey := "discovery:" + httpcache.URLToKey(urlStr)
	return d.cache.GetSet(ctx, cacheKey, doFetch, d.cache.TTL())
}

// isValidHexPubkey validates a 64-character hex string.
func isValidHexPubkey(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		isDigit := c >= '0' && c <= '9'
		isLowerHex := c >= 'a' && c <= 'f'
		isUpperHex := c >= 'A' && c <= 'F'
		if !isDigit && !isLowerHex && !isUpperHex {
			return false
		}
	}
	return true
}

// commonEmailProviders is a lookup set of common email providers to skip in WebFinger lookups.
var commonEmailProviders = map[string]bool{
	"gmail.com": true, "googlemail.com": true, "google.com": true,
	"yahoo.com": true, "yahoo.co.uk": true, "ymail.com": true,
	"hotmail.com": true, "outlook.com": true, "live.com": true, "msn.com": true,
	"icloud.com": true, "me.com": true, "mac.com": true,
	"aol.com": true, "protonmail.com": true, "proton.me": true,
	"fastmail.com": true, "fastmail.fm": true,
	"hey.com": true, "pm.me": true,
}
