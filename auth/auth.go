// Package auth provides cookie management for authenticated social media scraping.
package auth

import (
	"context"
	"net/http"
	"net/http/cookiejar"
	"net/url"
)

// NewCookieJar creates an http.CookieJar populated with the given cookies for a domain.
func NewCookieJar(domain string, cookies map[string]string) (*cookiejar.Jar, error) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse("https://" + domain)
	if err != nil {
		return nil, err
	}

	var httpCookies []*http.Cookie
	for name, value := range cookies {
		if value != "" {
			httpCookies = append(httpCookies, &http.Cookie{
				Name:   name,
				Value:  value,
				Domain: "." + domain,
				Path:   "/",
			})
		}
	}

	jar.SetCookies(u, httpCookies)
	return jar, nil
}

// Source represents a source of authentication cookies.
type Source interface {
	// Cookies returns cookies for the given platform, or nil if unavailable.
	Cookies(ctx context.Context, platform string) (map[string]string, error)
}

// ChainSources returns cookies from the first source that provides them.
func ChainSources(ctx context.Context, platform string, sources ...Source) (map[string]string, error) {
	for _, src := range sources {
		cookies, err := src.Cookies(ctx, platform)
		if err != nil {
			return nil, err
		}
		if len(cookies) > 0 {
			return cookies, nil
		}
	}
	return nil, nil //nolint:nilnil // no source had cookies, but this is not an error
}
