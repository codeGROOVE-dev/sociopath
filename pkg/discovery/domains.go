package discovery

import (
	"net/url"
	"strings"
)

// knownSocialDomains contains domains of established social platforms where
// identity discovery would be pointless.
var knownSocialDomains = map[string]bool{
	"github.com": true, "gitlab.com": true, "bitbucket.org": true, "codeberg.org": true,
	"twitter.com": true, "x.com": true, "facebook.com": true, "instagram.com": true,
	"linkedin.com": true, "tiktok.com": true, "youtube.com": true, "twitch.tv": true,
	"reddit.com": true, "discord.com": true, "slack.com": true, "telegram.org": true,
	"medium.com": true, "substack.com": true, "dev.to": true, "hashnode.dev": true,
	"stackoverflow.com": true, "stackexchange.com": true,
	"keybase.io": true, "bsky.app": true, "mastodon.social": true,
	"npmjs.com": true, "pypi.org": true, "rubygems.org": true, "crates.io": true,
	"hub.docker.com": true, "docker.io": true,
	"vk.com": true, "ok.ru": true, "weibo.com": true,
	"pinterest.com": true, "tumblr.com": true, "flickr.com": true,
	"soundcloud.com": true, "spotify.com": true, "bandcamp.com": true,
	"patreon.com": true, "ko-fi.com": true, "buymeacoffee.com": true,
	"linktree.com": true, "linktr.ee": true, "bio.link": true,
}

// hostingSuffixes contains common hosting platform suffixes.
var hostingSuffixes = []string{
	".github.io", ".gitlab.io", ".netlify.app", ".vercel.app", ".pages.dev",
}

// IsKnownSocialDomain returns true if the domain belongs to a known social platform.
func IsKnownSocialDomain(domain string) bool {
	domain = strings.ToLower(domain)

	if knownSocialDomains[domain] {
		return true
	}

	// Check if it's a subdomain of a known platform
	for known := range knownSocialDomains {
		if strings.HasSuffix(domain, "."+known) {
			return true
		}
	}

	// Check common hosting subdomains
	for _, suffix := range hostingSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	return false
}

// ExtractDomain extracts the domain from a URL, stripping www. prefix and lowercasing.
func ExtractDomain(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	host := strings.ToLower(parsed.Hostname())
	host = strings.TrimPrefix(host, "www.")
	return host
}
