package discovery

import (
	"net/url"
	"strings"
)

// knownSocialDomains contains domains of established social platforms and
// well-known projects where identity discovery would be pointless.
var knownSocialDomains = map[string]bool{
	// Code hosting
	"github.com": true, "github.blog": true, "gitlab.com": true, "bitbucket.org": true,
	"codeberg.org": true, "gitee.com": true, "sr.ht": true, "sourceforge.net": true,
	// Social media
	"twitter.com": true, "x.com": true, "facebook.com": true, "instagram.com": true,
	"linkedin.com": true, "tiktok.com": true, "youtube.com": true, "twitch.tv": true,
	"reddit.com": true, "discord.com": true, "slack.com": true, "telegram.org": true,
	"t.me": true, "whatsapp.com": true, "signal.org": true,
	// Blogging / Content
	"medium.com": true, "substack.com": true, "dev.to": true, "hashnode.dev": true,
	"wordpress.com": true, "blogger.com": true, "ghost.org": true,
	// Q&A / Forums
	"stackoverflow.com": true, "stackexchange.com": true,
	"quora.com": true, "news.ycombinator.com": true,
	// Identity / Social
	"keybase.io": true, "bsky.app": true, "mastodon.social": true,
	"hachyderm.io": true, "fosstodon.org": true, "infosec.exchange": true,
	"gravatar.com": true,
	// Package registries
	"npmjs.com": true, "pypi.org": true, "rubygems.org": true, "crates.io": true,
	"hex.pm": true, "packagist.org": true, "nuget.org": true,
	"hub.docker.com": true, "docker.io": true, "docker.com": true,
	"huggingface.co": true,
	// Regional social
	"vk.com": true, "ok.ru": true, "weibo.com": true, "bilibili.com": true,
	// Media sharing
	"pinterest.com": true, "tumblr.com": true, "flickr.com": true,
	"soundcloud.com": true, "spotify.com": true, "bandcamp.com": true,
	"dribbble.com": true, "behance.net": true,
	// Funding / Support
	"patreon.com": true, "ko-fi.com": true, "buymeacoffee.com": true,
	"opencollective.com": true, "gofundme.com": true,
	// Link aggregators
	"linktree.com": true, "linktr.ee": true, "bio.link": true,
	// Coding challenges
	"leetcode.com": true, "codewars.com": true, "hackerrank.com": true,
	"exercism.org": true, "freecodecamp.org": true, "codepen.io": true,
	"geeksforgeeks.org": true,
	// Security platforms
	"hackerone.com": true, "bugcrowd.com": true, "tryhackme.com": true,
	// Gaming
	"steam.com": true, "steamcommunity.com": true, "steampowered.com": true,
	// Programming languages (official sites - not personal domains)
	"python.org": true, "golang.org": true, "go.dev": true, "rust-lang.org": true,
	"ruby-lang.org": true, "nodejs.org": true, "deno.land": true, "typescriptlang.org": true,
	"kotlinlang.org": true, "swift.org": true, "scala-lang.org": true, "elixir-lang.org": true,
	"haskell.org": true, "clojure.org": true, "erlang.org": true, "julialang.org": true,
	"r-project.org": true, "perl.org": true, "php.net": true, "lua.org": true,
	"java.com": true, "oracle.com": true, "dotnet.microsoft.com": true,
	// Frameworks and libraries
	"reactjs.org": true, "react.dev": true, "vuejs.org": true, "angular.io": true,
	"svelte.dev": true, "nextjs.org": true, "nuxt.com": true, "astro.build": true,
	"remix.run": true, "gatsby.dev": true, "ember.com": true,
	"djangoproject.com": true, "rubyonrails.org": true, "laravel.com": true,
	"spring.io": true, "symfony.com": true, "flask.palletsprojects.com": true,
	"expressjs.com": true, "fastapi.tiangolo.com": true,
	// Infrastructure / DevOps
	"kubernetes.io": true, "terraform.io": true, "ansible.com": true,
	"nginx.org": true, "nginx.com": true,
	"aws.amazon.com": true, "cloud.google.com": true, "azure.microsoft.com": true,
	"digitalocean.com": true, "heroku.com": true, "railway.app": true, "render.com": true,
	// Operating systems / Foundations
	"linux.org": true, "kernel.org": true, "debian.org": true, "ubuntu.com": true,
	"fedoraproject.org": true, "archlinux.org": true, "freebsd.org": true,
	"mozilla.org": true, "chromium.org": true, "webkit.org": true,
	"apache.org": true, "eclipse.org": true, "cncf.io": true, "linuxfoundation.org": true,
	// Educational platforms
	"scratch.mit.edu": true, "khanacademy.org": true, "coursera.org": true,
	"udemy.com": true, "edx.org": true, "codecademy.com": true,
	// Search / Big tech
	"google.com": true, "microsoft.com": true, "apple.com": true, "amazon.com": true,
	"meta.com": true, "netflix.com": true,
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
