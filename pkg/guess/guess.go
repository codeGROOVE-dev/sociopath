// Package guess discovers related social media profiles based on known usernames.
package guess

import (
	"context"
	"log/slog"
	"maps"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

// Fetcher is a function that fetches a profile from a URL.
type Fetcher func(ctx context.Context, url string) (*profile.Profile, error)

// PlatformDetector is a function that returns the platform name for a URL.
type PlatformDetector func(url string) string

// Config holds configuration for guessing.
type Config struct {
	Logger           *slog.Logger
	Fetcher          Fetcher
	PlatformDetector PlatformDetector
}

// Popular Mastodon servers to check.
var mastodonServers = []string{
	"mastodon.social",
	"mastodon.online",
	"hachyderm.io",
	"fosstodon.org",
	"infosec.exchange",
	"mstdn.social",
	"mas.to",
	"techhub.social",
	"chaos.social",
}

// Platform URL patterns for username-based guessing.
// Note: weibo and zhihu are excluded because they require authentication
// and always redirect to login pages for unauthenticated users.
var platformPatterns = []struct {
	name    string
	pattern string // %s will be replaced with username
}{
	{"bluesky", "https://bsky.app/profile/%s.bsky.social"},
	{"twitter", "https://twitter.com/%s"},
	{"github", "https://github.com/%s"},
	{"gitlab", "https://gitlab.com/%s"},
	{"devto", "https://dev.to/%s"},
	{"instagram", "https://instagram.com/%s"},
	{"tiktok", "https://tiktok.com/@%s"},
	// LinkedIn removed from guessing - we can't verify profiles without auth
	{"bilibili", "https://space.bilibili.com/%s"},
	{"reddit", "https://reddit.com/user/%s"},
	{"replit", "https://replit.com/@%s"},
	{"youtube", "https://youtube.com/@%s"},
	{"medium", "https://medium.com/@%s"},
	{"habr", "https://habr.com/users/%s"},
	{"vkontakte", "https://vk.com/%s"},
	{"crates", "https://crates.io/users/%s"},
	{"dockerhub", "https://hub.docker.com/u/%s"},
	{"keybase", "https://keybase.io/%s"},
	{"arstechnica", "https://arstechnica.com/civis/search/8784651/?c[users]=%s&o=date"},
	{"codeberg", "https://codeberg.org/%s"},
	{"disqus", "https://disqus.com/by/%s"},
	{"hackernews", "https://news.ycombinator.com/user?id=%s"},
	{"lobsters", "https://lobste.rs/~%s"},
	{"twitch", "https://twitch.tv/%s"},
	{"hashnode", "https://hashnode.com/@%s"},
	{"hexpm", "https://hex.pm/users/%s"},
	{"qiita", "https://qiita.com/%s"},
	{"zenn", "https://zenn.dev/%s"},
	{"velog", "https://velog.io/@%s"},
	{"v2ex", "https://v2ex.com/member/%s"},
	{"gitee", "https://gitee.com/%s"},
	{"csdn", "https://blog.csdn.net/%s"},
	{"rubygems", "https://rubygems.org/profiles/%s"},
	{"leetcode", "https://leetcode.com/u/%s"},
	{"linktree", "https://linktr.ee/%s"},
	{"intensedebate", "https://intensedebate.com/people/%s"},
	{"sessionize", "https://sessionize.com/%s"},
	{"steam", "https://steamcommunity.com/id/%s"},
	{"douban", "https://www.douban.com/people/%s"},
	{"substack", "https://%s.substack.com"},
	{"npm", "https://www.npmjs.com/~%s"},
	{"pypi", "https://pypi.org/user/%s/"},
	{"dribbble", "https://dribbble.com/%s"},
	{"tryhackme", "https://tryhackme.com/p/%s"},
	{"bitbucket", "https://bitbucket.org/%s/"},
	{"huggingface", "https://huggingface.co/%s"},
	{"replit", "https://replit.com/@%s"},
	{"asciinema", "https://asciinema.org/~%s"},
	{"speakerdeck", "https://speakerdeck.com/%s"},
	{"hackerone", "https://hackerone.com/%s"},
	{"bugcrowd", "https://bugcrowd.com/%s"},
	{"codewars", "https://www.codewars.com/users/%s"},
	{"aboutme", "https://about.me/%s"},
	{"gumroad", "https://gumroad.com/%s"},
	{"scratch", "https://scratch.mit.edu/users/%s"},
	{"geeksforgeeks", "https://auth.geeksforgeeks.org/user/%s"},
	{"observable", "https://observablehq.com/@%s"},
	{"opencollective", "https://opencollective.com/%s"},
}

// isValidUsernameForPlatform checks if a username meets the platform's requirements.
// Each platform has different rules for valid usernames.
//
//nolint:gocognit,maintidx,staticcheck,revive // platform-specific validation; QF1001 De Morgan reduces readability
func isValidUsernameForPlatform(username, platform string) bool {
	switch platform {
	case "linkedin":
		// LinkedIn: 3-100 chars, alphanumeric and hyphens only, no consecutive hyphens,
		// cannot start/end with hyphen
		if len(username) < 3 || len(username) > 100 {
			return false
		}
		if strings.HasPrefix(username, "-") || strings.HasSuffix(username, "-") {
			return false
		}
		if strings.Contains(username, "--") {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		return true

	case "twitter":
		// Twitter/X: 4-15 chars, alphanumeric and underscores only
		if len(username) < 4 || len(username) > 15 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "github":
		// GitHub: 1-39 chars, alphanumeric and hyphens, cannot start with hyphen,
		// no consecutive hyphens
		if len(username) < 1 || len(username) > 39 {
			return false
		}
		if strings.HasPrefix(username, "-") {
			return false
		}
		if strings.Contains(username, "--") {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		return true

	case "instagram":
		// Instagram: 1-30 chars, alphanumeric, underscores, and periods
		// Cannot have consecutive periods, cannot start/end with period
		if len(username) < 1 || len(username) > 30 {
			return false
		}
		if strings.HasPrefix(username, ".") || strings.HasSuffix(username, ".") {
			return false
		}
		if strings.Contains(username, "..") {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.') {
				return false
			}
		}
		return true

	case "tiktok":
		// TikTok: 2-24 chars, alphanumeric, underscores, and periods
		if len(username) < 2 || len(username) > 24 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.') {
				return false
			}
		}
		return true

	case "reddit":
		// Reddit: 3-20 chars, alphanumeric and underscores, hyphens allowed
		if len(username) < 3 || len(username) > 20 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "replit":
		// Replit: 1-39 chars, must start with letter, alphanumeric, underscores, hyphens
		if len(username) < 1 || len(username) > 39 {
			return false
		}
		first := username[0]
		if !((first >= 'a' && first <= 'z') || (first >= 'A' && first <= 'Z')) {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "youtube":
		// YouTube handles: 3-30 chars, alphanumeric, underscores, hyphens, periods
		if len(username) < 3 || len(username) > 30 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.') {
				return false
			}
		}
		return true

	case "medium", "mastodon", "devto", "habr", "observable":
		// These platforms share similar rules: 1-30 chars, alphanumeric and underscores
		if len(username) < 1 || len(username) > 30 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "bluesky":
		// Bluesky handles: 3-20 chars before .bsky.social, alphanumeric and hyphens
		// Cannot start/end with hyphen
		if len(username) < 3 || len(username) > 20 {
			return false
		}
		if strings.HasPrefix(username, "-") || strings.HasSuffix(username, "-") {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		return true

	case "vkontakte":
		// VK: alphanumeric and underscores, 5-32 chars
		if len(username) < 5 || len(username) > 32 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "bilibili":
		// Bilibili uses numeric user IDs, not usernames
		for _, c := range username {
			if c < '0' || c > '9' {
				return false
			}
		}
		return username != ""

	case "weibo", "zhihu":
		// These platforms use various ID formats, be permissive
		return len(username) >= 1 && len(username) <= 50

	case "gitlab":
		// GitLab: 2-255 chars, alphanumeric, underscores, hyphens, periods
		// Cannot start/end with hyphen, period, or underscore
		// Cannot have consecutive special characters
		if len(username) < 2 || len(username) > 255 {
			return false
		}
		first, last := username[0], username[len(username)-1]
		if first == '-' || first == '.' || first == '_' ||
			last == '-' || last == '.' || last == '_' {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
		return true

	case "crates":
		// crates.io: alphanumeric, underscores, hyphens
		// Similar to GitHub username rules
		if len(username) < 1 || len(username) > 64 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
		return true

	case "dockerhub":
		// Docker Hub: 4-30 chars, lowercase alphanumeric, underscores, hyphens
		// Cannot start with hyphen or underscore
		if len(username) < 4 || len(username) > 30 {
			return false
		}
		first := username[0]
		if first == '-' || first == '_' {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
				return false
			}
		}
		return true

	case "keybase":
		// Keybase: 2-16 chars, lowercase alphanumeric, underscores
		if len(username) < 2 || len(username) > 16 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "arstechnica":
		// Ars Technica forum: 3-50 chars, alphanumeric, underscores, hyphens
		if len(username) < 3 || len(username) > 50 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "codeberg", "gitee", "bitbucket", "huggingface", "speakerdeck", "aboutme", "gumroad", "opencollective":
		// Similar to GitHub: 1-39 chars, alphanumeric and hyphens
		if len(username) < 1 || len(username) > 39 {
			return false
		}
		if strings.HasPrefix(username, "-") {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		return true

	case "disqus", "intensedebate":
		// Comment platforms: 3-30 chars, alphanumeric, underscores, hyphens
		if len(username) < 3 || len(username) > 30 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "hackernews":
		// HN: 2-15 chars, alphanumeric, underscores
		if len(username) < 2 || len(username) > 15 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "lobsters":
		// Lobsters: 2-24 chars, alphanumeric, underscores
		if len(username) < 2 || len(username) > 24 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "twitch":
		// Twitch: 4-25 chars, alphanumeric, underscores
		if len(username) < 4 || len(username) > 25 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "hashnode", "velog":
		// Blog platforms: 3-30 chars, alphanumeric, underscores, hyphens
		if len(username) < 3 || len(username) > 30 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "hexpm", "rubygems", "npm", "pypi":
		// Package registries: 2-40 chars, alphanumeric, underscores, hyphens
		if len(username) < 2 || len(username) > 40 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "qiita", "zenn":
		// Japanese dev platforms: 3-24 chars, alphanumeric, underscores
		if len(username) < 3 || len(username) > 24 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "v2ex", "csdn":
		// Chinese dev platforms: 3-30 chars, alphanumeric, underscores, hyphens
		if len(username) < 3 || len(username) > 30 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "leetcode", "hackerone", "bugcrowd", "codewars":
		// Coding challenge/security platforms: 3-20 chars, alphanumeric, underscores, hyphens
		if len(username) < 3 || len(username) > 20 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "linktree", "dribbble", "scratch", "geeksforgeeks":
		// Platforms with underscores and periods: 3-30 chars, alphanumeric, underscores, periods
		if len(username) < 3 || len(username) > 30 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.') {
				return false
			}
		}
		return true

	case "sessionize":
		// Sessionize: 3-50 chars, alphanumeric, underscores, hyphens
		if len(username) < 3 || len(username) > 50 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
				return false
			}
		}
		return true

	case "steam", "tryhackme", "asciinema":
		// Gaming/security/dev platforms: 3-32 chars, alphanumeric, underscores
		if len(username) < 3 || len(username) > 32 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
				return false
			}
		}
		return true

	case "douban":
		// Douban: alphanumeric, hyphens, 1-30 chars
		if len(username) < 1 || len(username) > 30 {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		return true

	case "substack":
		// Substack subdomains: 3-63 chars, alphanumeric, hyphens (valid subdomain)
		if len(username) < 3 || len(username) > 63 {
			return false
		}
		if strings.HasPrefix(username, "-") || strings.HasSuffix(username, "-") {
			return false
		}
		for _, c := range username {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-') {
				return false
			}
		}
		return true

	default:
		// Unknown platform, be permissive
		return len(username) >= 1
	}
}

// Related discovers related profiles based on known profiles.
// It extracts usernames and tries to find matching profiles on other platforms.
//
//nolint:gocognit,maintidx,nestif,revive // multi-stage profile discovery with concurrent fetching is inherently complex
func Related(ctx context.Context, known []*profile.Profile, cfg Config) []*profile.Profile {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Extract all known usernames
	usernames := extractUsernamesWithLogger(known, cfg.Logger)
	cfg.Logger.Debug("extracted usernames for guessing", "count", len(usernames))

	// Extract names for LinkedIn slug guessing
	names := extractNames(known)
	cfg.Logger.Debug("extracted names for guessing", "count", len(names))

	// Build set of already known URLs to avoid duplicates
	knownURLs := make(map[string]bool)
	knownPlatforms := make(map[string]bool)   // Platforms we have profiles for (guessed or vouched)
	vouchedPlatforms := make(map[string]bool) // Platforms from vouched sources only
	for _, p := range known {
		knownURLs[normalizeURL(p.URL)] = true
		knownPlatforms[p.Platform] = true
		vouchedPlatforms[p.Platform] = true
		// Also mark platforms from social links as vouched - these are verified URLs
		// that we'll fetch directly, so no need to guess for these platforms
		for _, link := range p.SocialLinks {
			knownURLs[normalizeURL(link)] = true
			if cfg.PlatformDetector != nil {
				if platform := cfg.PlatformDetector(link); platform != "" && platform != "website" {
					knownPlatforms[platform] = true
					vouchedPlatforms[platform] = true
				}
			}
		}
	}

	// Generate candidate URLs
	// Pass vouchedPlatforms for name-based guessing (we skip only if vouched)
	candidates := generateCandidates(usernames, names, knownURLs, knownPlatforms, vouchedPlatforms)
	cfg.Logger.Info("generated guess candidates", "count", len(candidates))

	// Fetch candidates concurrently
	var guessed []*profile.Profile
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(candidate candidateURL) {
			defer wg.Done()

			fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			cfg.Logger.Debug("trying guess candidate", "url", candidate.url, "username", candidate.username)

			p, err := cfg.Fetcher(fetchCtx, candidate.url)
			if err != nil {
				cfg.Logger.Info("guess candidate failed", "url", candidate.url, "error", err)
				return
			}

			// Score the match against known profiles
			confidence, matches := scoreMatch(p, known, candidate)
			if confidence < 0.3 {
				cfg.Logger.Info("guess candidate low confidence, skipping", "url", candidate.url, "confidence", confidence)
				return
			}

			p.IsGuess = true
			p.Confidence = confidence
			p.GuessMatch = matches

			cfg.Logger.Info("found guessed profile", "url", p.URL, "confidence", confidence, "matches", matches)

			mu.Lock()
			guessed = append(guessed, p)
			mu.Unlock()
		}(c)
	}

	wg.Wait()

	// Second round: Fetch social links and extract usernames from guessed profiles
	// This handles cases like finding "thomrstrom" from a Mastodon link in a GitHub profile
	if len(guessed) > 0 {
		// Update knownPlatforms with platforms discovered in first round
		for _, p := range guessed {
			knownPlatforms[p.Platform] = true
		}

		// Collect social links from guessed profiles to fetch directly
		var socialLinksToFetch []string
		for _, p := range guessed {
			for _, link := range p.SocialLinks {
				normalized := normalizeURL(link)
				if knownURLs[normalized] {
					continue
				}
				// For high-confidence profiles (>=0.6), always fetch their social links
				// even if we already have that platform - the linked profile may be
				// the correct one while our guess may be wrong
				if p.Confidence >= 0.6 {
					socialLinksToFetch = append(socialLinksToFetch, link)
					knownURLs[normalized] = true
					continue
				}
				// For lower confidence profiles, skip if we already have this platform
				if cfg.PlatformDetector != nil {
					linkPlatform := cfg.PlatformDetector(link)
					if linkPlatform != "" && linkPlatform != "website" && knownPlatforms[linkPlatform] {
						continue
					}
				}
				socialLinksToFetch = append(socialLinksToFetch, link)
				knownURLs[normalized] = true
			}
			// Also check website field (websites are generic, always fetch)
			if p.Website != "" {
				normalized := normalizeURL(p.Website)
				if !knownURLs[normalized] {
					socialLinksToFetch = append(socialLinksToFetch, p.Website)
					knownURLs[normalized] = true
				}
			}
			// Mark the guessed profile itself as known
			knownURLs[normalizeURL(p.URL)] = true
		}

		// Fetch social links directly (these are verified links, high confidence)
		if len(socialLinksToFetch) > 0 {
			cfg.Logger.Info("second round: fetching discovered social links", "count", len(socialLinksToFetch))

			for _, link := range socialLinksToFetch {
				if ctx.Err() != nil {
					break
				}

				wg.Add(1)
				go func(url string) {
					defer wg.Done()

					fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()

					cfg.Logger.Debug("fetching discovered social link", "url", url)

					p, err := cfg.Fetcher(fetchCtx, url)
					if err != nil {
						cfg.Logger.Info("social link fetch failed", "url", url, "error", err)
						return
					}

					// Score against ALL known profiles (original + first round guesses)
					allKnown := make([]*profile.Profile, 0, len(known)+len(guessed))
					allKnown = append(allKnown, known...)
					allKnown = append(allKnown, guessed...)
					confidence, matches := scoreMatch(p, allKnown, candidateURL{
						url:       url,
						username:  p.Username,
						platform:  p.Platform,
						matchType: "linked", // This is a verified link
					})

					// Lower threshold for linked profiles since they were directly referenced
					if confidence < 0.25 {
						cfg.Logger.Info("social link low confidence, skipping",
							"url", url, "confidence", confidence)
						return
					}

					p.IsGuess = true
					p.Confidence = confidence
					p.GuessMatch = matches

					cfg.Logger.Info("found profile from social link",
						"url", p.URL, "confidence", confidence, "matches", matches)

					mu.Lock()
					guessed = append(guessed, p)
					mu.Unlock()
				}(link)
			}

			wg.Wait()
		}

		// Also extract usernames for username-based guessing
		secondRoundUsernames := extractUsernamesWithLogger(guessed, cfg.Logger)
		// For name-based guessing (especially LinkedIn), only use names from high-confidence profiles
		// to avoid using incorrect names from low-confidence guesses (e.g., "Trevor Pope" from TikTok
		// when the original GitHub profile has "Tim Pope")
		highConfidenceGuessed := filterHighConfidenceForNames(guessed)
		secondRoundNames := extractNames(highConfidenceGuessed)

		// Only generate candidates for NEW usernames/names not already tried
		newUsernames := make([]string, 0)
		for _, u := range secondRoundUsernames {
			if !slices.Contains(usernames, u) {
				newUsernames = append(newUsernames, u)
			}
		}

		newNames := make([]string, 0)
		for _, n := range secondRoundNames {
			if !slices.Contains(names, n) {
				newNames = append(newNames, n)
			}
		}

		if len(newUsernames) > 0 || len(newNames) > 0 {
			cfg.Logger.Debug("second round: found new usernames from guessed profiles",
				"new_usernames", len(newUsernames), "new_names", len(newNames))

			secondCandidates := generateCandidates(newUsernames, newNames, knownURLs, knownPlatforms, vouchedPlatforms)
			cfg.Logger.Info("generated second round candidates", "count", len(secondCandidates))

			// Fetch second round candidates
			for _, c := range secondCandidates {
				if ctx.Err() != nil {
					break
				}

				wg.Add(1)
				go func(candidate candidateURL) {
					defer wg.Done()

					fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
					defer cancel()

					cfg.Logger.Debug("trying second round candidate", "url", candidate.url, "username", candidate.username)

					p, err := cfg.Fetcher(fetchCtx, candidate.url)
					if err != nil {
						cfg.Logger.Info("second round candidate failed", "url", candidate.url, "error", err)
						return
					}

					// Score against ALL known profiles (original + first round guesses)
					allKnown := make([]*profile.Profile, 0, len(known)+len(guessed))
					allKnown = append(allKnown, known...)
					allKnown = append(allKnown, guessed...)
					confidence, matches := scoreMatch(p, allKnown, candidate)
					if confidence < 0.3 {
						cfg.Logger.Info("second round candidate low confidence, skipping",
							"url", candidate.url, "confidence", confidence)
						return
					}

					p.IsGuess = true
					p.Confidence = confidence
					p.GuessMatch = matches

					cfg.Logger.Info("found second round guessed profile",
						"url", p.URL, "confidence", confidence, "matches", matches)

					mu.Lock()
					guessed = append(guessed, p)
					mu.Unlock()
				}(c)
			}

			wg.Wait()
		}
	}

	// Retrospective rescoring: Now that we have all profiles (including GitHub with orgs),
	// rescore earlier guesses that might benefit from newly discovered information.
	// Use iterative rescoring - profiles that reach 1.0 can help boost others in subsequent rounds.
	if len(guessed) > 0 {
		maxRounds := 3 // Prevent infinite loops
		totalRescored := false

		for round := range maxRounds {
			// Build list of high-confidence profiles (known + guessed with 1.0 confidence)
			var highConfidence []*profile.Profile
			highConfidence = append(highConfidence, known...)
			for _, p := range guessed {
				if p.Confidence == 1.0 {
					highConfidence = append(highConfidence, p)
				}
			}

			roundRescored := false

			for i, p := range guessed {
				// Skip if already at 1.0 confidence
				if p.Confidence == 1.0 {
					continue
				}

				// Rescore this profile against only high-confidence profiles
				newConfidence, newMatches := scoreMatch(p, highConfidence, candidateURL{
					url:       p.URL,
					username:  p.Username,
					platform:  p.Platform,
					matchType: "username",
				})

				// Update if confidence improved
				if newConfidence > p.Confidence {
					cfg.Logger.Debug("retrospective rescore improved confidence",
						"url", p.URL,
						"round", round+1,
						"old_confidence", p.Confidence,
						"new_confidence", newConfidence,
						"new_matches", newMatches)
					guessed[i].Confidence = newConfidence
					guessed[i].GuessMatch = newMatches
					roundRescored = true
					totalRescored = true
				}
			}

			// If no changes in this round, we're done
			if !roundRescored {
				break
			}
		}

		if totalRescored {
			cfg.Logger.Info("retrospective rescoring updated confidences")
		}
	}

	// Filter to only highest confidence per platform
	guessed = filterHighestConfidencePerPlatform(guessed)

	// Sort for deterministic output (platform, then URL)
	sort.Slice(guessed, func(i, j int) bool {
		if guessed[i].Platform != guessed[j].Platform {
			return guessed[i].Platform < guessed[j].Platform
		}
		return guessed[i].URL < guessed[j].URL
	})

	return guessed
}

// filterHighestConfidencePerPlatform keeps only the highest confidence profile(s) per platform.
// If multiple profiles are tied at the highest confidence, all are kept (but duplicates by URL are removed).
func filterHighestConfidencePerPlatform(profiles []*profile.Profile) []*profile.Profile {
	if len(profiles) == 0 {
		return profiles
	}

	// Group profiles by platform and find max confidence per platform
	byPlatform := make(map[string][]*profile.Profile)
	maxConfidence := make(map[string]float64)

	for _, p := range profiles {
		byPlatform[p.Platform] = append(byPlatform[p.Platform], p)
		if p.Confidence > maxConfidence[p.Platform] {
			maxConfidence[p.Platform] = p.Confidence
		}
	}

	// Keep only profiles at max confidence for their platform, deduplicating by normalized URL
	var result []*profile.Profile
	seenURLs := make(map[string]bool)

	for platform, platformProfiles := range byPlatform {
		maxConf := maxConfidence[platform]
		for _, p := range platformProfiles {
			if p.Confidence == maxConf {
				normalizedURL := normalizeURL(p.URL)
				if !seenURLs[normalizedURL] {
					seenURLs[normalizedURL] = true
					result = append(result, p)
				}
			}
		}
	}

	return result
}

type candidateURL struct {
	url        string
	username   string
	platform   string
	matchType  string // "username" or "name"
	sourceName string // for name-based matches, store the original name
}

func extractUsernames(profiles []*profile.Profile) []string {
	return extractUsernamesWithLogger(profiles, nil)
}

func extractUsernamesWithLogger(profiles []*profile.Profile, logger *slog.Logger) []string {
	seen := make(map[string]bool)
	var usernames []string

	for _, p := range profiles {
		// Only use verified usernames from successfully fetched profiles
		if p.Username != "" && isSocialPlatform(p.Platform) {
			u := strings.ToLower(p.Username)

			// Skip LinkedIn usernames with auto-generated numeric suffixes
			// e.g., "john-doe-123456789" - these won't be reused on other platforms
			if p.Platform == "linkedin" && hasAutoGeneratedSuffix(u) {
				if logger != nil {
					logger.Debug("skipping linkedin username with auto-generated suffix",
						"username", u, "source_url", p.URL)
				}
				continue
			}

			if isValidUsername(u) && !seen[u] {
				seen[u] = true
				usernames = append(usernames, u)
				if logger != nil {
					logger.Debug("discovered username for guessing",
						"username", u, "source_platform", p.Platform, "source_url", p.URL)
				}
			}
		}
	}

	return usernames
}

// hasAutoGeneratedSuffix checks if a LinkedIn slug has an auto-generated numeric suffix.
// LinkedIn generates slugs like "firstname-lastname-123456789" where the suffix is random.
func hasAutoGeneratedSuffix(slug string) bool {
	// Find the last hyphen
	lastHyphen := strings.LastIndex(slug, "-")
	if lastHyphen == -1 || lastHyphen == len(slug)-1 {
		return false
	}

	suffix := slug[lastHyphen+1:]

	// Auto-generated suffixes are typically 6+ digits
	if len(suffix) < 6 {
		return false
	}

	// Check if suffix is all digits
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}

	return true
}

// filterHighConfidenceForNames returns only profiles with confidence >= 0.6 for name extraction.
// This prevents low-confidence guesses (like finding "Trevor Pope" on TikTok when looking
// for "Tim Pope") from polluting name-based candidate generation.
func filterHighConfidenceForNames(profiles []*profile.Profile) []*profile.Profile {
	var result []*profile.Profile
	for _, p := range profiles {
		// Only include profiles with confidence >= 0.6, or non-guess profiles (always trusted)
		if !p.IsGuess || p.Confidence >= 0.6 {
			result = append(result, p)
		}
	}
	return result
}

// extractNames extracts full names from profiles for name-based guessing (e.g., LinkedIn slugs).
func extractNames(profiles []*profile.Profile) []string {
	seen := make(map[string]bool)
	var names []string

	for _, p := range profiles {
		if p.Name == "" || !isSocialPlatform(p.Platform) {
			continue
		}

		name := strings.TrimSpace(p.Name)
		// Skip if too short or looks like a username (no spaces)
		if len(name) < 3 || !strings.Contains(name, " ") {
			continue
		}

		// Normalize and dedupe
		nameKey := strings.ToLower(name)
		if !seen[nameKey] {
			seen[nameKey] = true
			names = append(names, name)
		}
	}

	return names
}

// slugifyName converts a name to a LinkedIn-style slug.
// "David E Worth" -> "david-e-worth".
// "John O'Brien" -> "john-o-brien".
func slugifyName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))

	// Replace spaces and common punctuation with hyphens
	name = strings.ReplaceAll(name, " ", "-")
	name = strings.ReplaceAll(name, ".", "-")

	// Remove or replace special characters
	var result strings.Builder
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' {
			result.WriteRune(r)
		} else if r == '\'' || r == '\u2019' {
			// Keep apostrophes for names like O'Brien (both straight and curly quotes)
			result.WriteRune('-')
		}
		// Skip other characters
	}

	slug := result.String()

	// Clean up multiple consecutive hyphens
	for strings.Contains(slug, "--") {
		slug = strings.ReplaceAll(slug, "--", "-")
	}

	// Trim leading/trailing hyphens
	slug = strings.Trim(slug, "-")

	return slug
}

func isSocialPlatform(platform string) bool {
	// Platforms that should NOT be used for username extraction/guessing
	nonSocial := map[string]bool{
		"website": true, // generic websites don't have meaningful usernames
	}
	return !nonSocial[strings.ToLower(platform)]
}

func isValidUsername(u string) bool {
	// Skip very short usernames (too generic)
	if len(u) < 3 {
		return false
	}

	// Skip common non-username strings (page paths, not user profiles)
	invalid := map[string]bool{
		"users": true, "user": true, "profile": true, "settings": true,
		"about": true, "help": true, "terms": true, "privacy": true,
		"home": true, "index": true, "search": true, "login": true,
		"logout": true, "signup": true, "register": true, "api": true,
		"people":    true, // e.g., intensedebate.com/people is a directory, not a profile
		"civis":     true, // e.g., arstechnica.com/civis is a forum, not a profile
		"slideshow": true, // e.g., slideshare.net/slideshow is a content path, not a profile
	}
	return !invalid[u]
}

// maxCandidatesPerPlatform limits how many URLs we try per platform to avoid excessive requests.
const maxCandidatesPerPlatform = 3

func generateCandidates(
	usernames []string,
	_ []string, // names - unused after removing LinkedIn name-based guessing
	knownURLs map[string]bool,
	knownPlatforms map[string]bool,
	_ map[string]bool, // vouchedPlatforms - unused after removing LinkedIn name-based guessing
) []candidateURL {
	// Track candidates per platform, prioritizing higher-quality guesses
	platformCandidates := make(map[string][]candidateURL)

	// Sort usernames by quality (longer usernames with digits are more unique)
	sortedUsernames := make([]string, len(usernames))
	copy(sortedUsernames, usernames)
	sort.Slice(sortedUsernames, func(i, j int) bool {
		return usernameQuality(sortedUsernames[i]) > usernameQuality(sortedUsernames[j])
	})

	// Generate username-based candidates
	for _, username := range sortedUsernames {
		// Add platform patterns
		for _, pp := range platformPatterns {
			// Skip platforms we already have a verified profile for
			if knownPlatforms[pp.name] {
				continue
			}

			// Skip if we already have enough candidates for this platform
			if len(platformCandidates[pp.name]) >= maxCandidatesPerPlatform {
				continue
			}

			// Skip if username doesn't meet platform requirements
			if !isValidUsernameForPlatform(username, pp.name) {
				continue
			}

			url := strings.Replace(pp.pattern, "%s", username, 1)
			if !knownURLs[normalizeURL(url)] {
				platformCandidates[pp.name] = append(platformCandidates[pp.name], candidateURL{
					url:       url,
					username:  username,
					platform:  pp.name,
					matchType: "username",
				})
			}
		}

		// Add Mastodon servers only if we don't already have a Mastodon profile
		if !knownPlatforms["mastodon"] && len(platformCandidates["mastodon"]) < maxCandidatesPerPlatform {
			// Check if username is valid for Mastodon
			if !isValidUsernameForPlatform(username, "mastodon") {
				continue
			}
			for _, server := range mastodonServers {
				if len(platformCandidates["mastodon"]) >= maxCandidatesPerPlatform {
					break
				}
				url := "https://" + server + "/@" + username
				if !knownURLs[normalizeURL(url)] {
					platformCandidates["mastodon"] = append(platformCandidates["mastodon"], candidateURL{
						url:       url,
						username:  username,
						platform:  "mastodon",
						matchType: "username",
					})
				}
			}
		}
	}

	// LinkedIn name-based guessing removed - we can't verify profiles without auth
	// LinkedIn profiles will only be included when discovered via actual links

	// Flatten the map into a slice
	var candidates []candidateURL
	for _, platformCands := range platformCandidates {
		candidates = append(candidates, platformCands...)
	}

	return candidates
}

// usernameQuality returns a score for how unique/reliable a username is for guessing.
// Higher scores = better quality (longer usernames, usernames with digits).
func usernameQuality(username string) int {
	score := len(username)

	// Usernames with digits are more unique
	if containsDigit(username) {
		score += 5
	}

	// Usernames with underscores or dots are often more unique
	if strings.ContainsAny(username, "_.") {
		score += 3
	}

	return score
}

// containsDigit returns true if the string contains at least one digit.
func containsDigit(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

func normalizeURL(url string) string {
	url = strings.TrimSuffix(url, "/")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "www.")
	url = strings.ToLower(url)
	// Normalize x.com to twitter.com (they're the same platform)
	url = strings.Replace(url, "x.com/", "twitter.com/", 1)
	// Normalize Mastodon web interface URLs to canonical profile URLs
	// e.g., triangletoot.party/web/@username -> triangletoot.party/@username
	url = strings.Replace(url, "/web/@", "/@", 1)
	return url
}

// scoreMatch calculates confidence that a guessed profile belongs to the same person.
// Returns confidence (0.0-1.0) and list of matching criteria.
//
//nolint:gocognit,maintidx,revive // multi-signal confidence scoring with extensive heuristics is inherently complex
func scoreMatch(guessed *profile.Profile, known []*profile.Profile, candidate candidateURL) (confidence float64, matchReasons []string) {
	var score float64
	var matches []string

	targetUsername := candidate.username
	matchType := candidate.matchType

	// Base score depends on match type
	if matchType == "name" {
		// Name-based slug matches start with low base confidence.
		// Simple slugs like "max-allan" are common and need more corroborating signals.
		// Complex slugs with numbers/suffixes like "max-allan-cgr" or "m4x4ll4n" are more unique.
		if isComplexSlug(candidate.username) {
			score += 0.15
			matches = append(matches, "name:slug-complex")
		} else {
			score += 0.10
			matches = append(matches, "name:slug")
		}
	} else {
		// Username match scoring
		guessedUser := strings.ToLower(guessed.Username)

		// Username match scoring - penalize only very short/common usernames
		if guessedUser == targetUsername {
			// Very short usernames (3-4 chars) without digits are likely common names
			if len(targetUsername) <= 4 && !containsDigit(targetUsername) {
				score += 0.1
			} else {
				score += 0.3
			}
			matches = append(matches, "username:exact")
		} else if strings.Contains(guessedUser, targetUsername) || strings.Contains(targetUsername, guessedUser) {
			score += 0.1
			matches = append(matches, "username:substring")
		}
	}

	// Track best signals (don't accumulate across profiles)
	var hasLink bool
	var bestNameScore, bestLocScore, bestBioScore float64
	var hasWebsiteMatch, hasEmployerMatch, hasOrgMatch, hasInterestMatch bool

	// Check against each known profile for additional signals
	for _, kp := range known {
		// Check for links between profiles (highest signal)
		if hasLinkTo(guessed, kp) || hasLinkTo(kp, guessed) {
			if !hasLink {
				hasLink = true
				matches = append(matches, "linked:"+kp.Platform)
			}
		}

		// Check name similarity (high signal) - track best score
		if nameScore := scoreName(guessed.Name, kp.Name); nameScore > bestNameScore {
			if bestNameScore == 0 {
				matches = append(matches, "name:"+kp.Platform)
			}
			bestNameScore = nameScore
		}

		// Check location match (medium signal) - track best score
		if locScore := scoreLocation(guessed.Location, kp.Location); locScore > bestLocScore {
			if bestLocScore == 0 {
				matches = append(matches, "location:"+kp.Platform)
			}
			bestLocScore = locScore
		}

		// Check bio word overlap (lower signal) - track best score
		if bioScore := scoreBioOverlap(guessed.Bio, kp.Bio); bioScore > bestBioScore {
			if bestBioScore == 0 {
				matches = append(matches, "bio:"+kp.Platform)
			}
			bestBioScore = bioScore
		}

		// Check website match (high signal)
		if guessed.Website != "" && kp.Website != "" {
			if normalizeURL(guessed.Website) == normalizeURL(kp.Website) {
				if !hasWebsiteMatch {
					hasWebsiteMatch = true
					matches = append(matches, "website:"+kp.Platform)
				}
			}
		}

		// Check employer/company match (high signal, especially for name-based LinkedIn guesses)
		if !hasEmployerMatch {
			guessedEmployer := ""
			knownEmployer := ""

			// Extract employer from guessed profile (LinkedIn uses "employer", GitHub uses "company")
			if guessed.Fields != nil {
				if emp := guessed.Fields["employer"]; emp != "" {
					guessedEmployer = strings.ToLower(strings.TrimSpace(emp))
				} else if comp := guessed.Fields["company"]; comp != "" {
					guessedEmployer = strings.ToLower(strings.TrimSpace(comp))
				}
			}

			// Extract employer from known profile
			if kp.Fields != nil {
				if emp := kp.Fields["employer"]; emp != "" {
					knownEmployer = strings.ToLower(strings.TrimSpace(emp))
				} else if comp := kp.Fields["company"]; comp != "" {
					knownEmployer = strings.ToLower(strings.TrimSpace(comp))
				}
			}

			// Check for employer match
			if guessedEmployer != "" && knownEmployer != "" {
				// Remove spaces for more flexible matching (e.g., "defenseunicorns" vs "defense unicorns")
				guessedNoSpace := strings.ReplaceAll(guessedEmployer, " ", "")
				knownNoSpace := strings.ReplaceAll(knownEmployer, " ", "")

				// Exact match or one contains the other (e.g., "Google" vs "Google LLC")
				if guessedEmployer == knownEmployer ||
					strings.Contains(guessedEmployer, knownEmployer) ||
					strings.Contains(knownEmployer, guessedEmployer) ||
					strings.Contains(guessedNoSpace, knownNoSpace) ||
					strings.Contains(knownNoSpace, guessedNoSpace) {
					hasEmployerMatch = true
					matches = append(matches, "employer:"+kp.Platform)
				}
			}
		}

		// Check organization match (GitHub organizations vs bio/employer/unstructured mentions)
		if !hasOrgMatch {
			// Get organizations from either profile (usually GitHub)
			guessedOrgs := extractOrganizationList(guessed.Fields)
			knownOrgs := extractOrganizationList(kp.Fields)

			// Check if any organization appears in the other profile's bio, employer, unstructured, or posts
			if len(guessedOrgs) > 0 || len(knownOrgs) > 0 {
				// Check guessed orgs against known bio/employer/unstructured/posts
				if len(guessedOrgs) > 0 && scoreOrganizationMatch(guessedOrgs, kp.Bio, getEmployer(kp.Fields), kp.Unstructured+" "+postsText(kp)) {
					hasOrgMatch = true
					matches = append(matches, "organization:"+kp.Platform)
				}
				// Check known orgs against guessed bio/employer/unstructured/posts
				if !hasOrgMatch && len(knownOrgs) > 0 && scoreOrganizationMatch(knownOrgs, guessed.Bio, getEmployer(guessed.Fields), guessed.Unstructured+" "+postsText(guessed)) {
					hasOrgMatch = true
					matches = append(matches, "organization:"+kp.Platform)
				}
			}

			// Also check if guessed employer matches any known org directly
			// E.g., LinkedIn employer "Chainguard" should match GitHub org "chainguard-dev" (normalized to "chainguard")
			if !hasOrgMatch && len(knownOrgs) > 0 {
				guessedEmployer := strings.ToLower(getEmployer(guessed.Fields))
				if guessedEmployer != "" {
					for _, org := range knownOrgs {
						if strings.Contains(guessedEmployer, org) || strings.Contains(org, guessedEmployer) {
							hasOrgMatch = true
							matches = append(matches, "organization:"+kp.Platform)
							break
						}
					}
				}
			}
		}

		// Check interest match (Reddit subreddits matching GitHub bio/interests, or shared bio topics)
		if !hasInterestMatch {
			if scoreInterestMatch(guessed, kp) {
				hasInterestMatch = true
				matches = append(matches, "interest:"+kp.Platform)
			}
		}
	}

	// Add best signals to score (only once, not per profile)
	if hasLink {
		score += 0.5
	}
	if bestNameScore > 0 {
		// Name match alone shouldn't push score too high for name-based LinkedIn guesses
		// For username-based matches, name match is a stronger signal
		if matchType == "name" {
			score += bestNameScore * 0.15
		} else {
			score += bestNameScore * 0.3
		}
	}
	if bestLocScore > 0 {
		score += bestLocScore * 0.15
	}
	if bestBioScore > 0 {
		score += bestBioScore * 0.1
	}
	if hasWebsiteMatch {
		score += 0.4
	}
	if hasEmployerMatch {
		// Employer match is a strong signal, especially for name-based LinkedIn guesses
		score += 0.35
	}
	if hasOrgMatch {
		// Organization match is a strong signal (e.g., GitHub org matches bio mention)
		score += 0.30
	}
	if hasInterestMatch {
		// Interest match (e.g., Reddit subreddit "vim" matches GitHub bio "Vim plugin artist")
		score += 0.25
	}

	// Tech title bonus: if the profile has a tech-related title, it's more likely to be the same person
	// This is especially valuable when combined with other signals like org/employer match
	hasTechTitleMatch := false
	title := ""
	if guessed.Fields != nil {
		title = guessed.Fields["title"]
	}
	if hasTechTitle(guessed.Bio) || hasTechTitle(title) {
		hasTechTitleMatch = true
		// Tech title alone is a weak signal, but combined with org/employer match it's strong
		if hasOrgMatch || hasEmployerMatch {
			score += 0.10
			matches = append(matches, "title:tech")
		}
	}

	// Strong signal combination bonus: name + org/employer + tech title together are very reliable
	if (hasOrgMatch || hasEmployerMatch) && bestNameScore > 0.5 && hasTechTitleMatch {
		score += 0.15
		matches = append(matches, "combo:name+org+tech")
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	// For LinkedIn name-based matches without strong signals (employer, location, link),
	// require a tech-related job title to avoid false positives from common names.
	// A "Career Coach" or "Partner at Law Firm" with the same name is unlikely to be the same person.
	if guessed.Platform == "linkedin" && matchType == "name" &&
		!hasLink && !hasEmployerMatch && !hasOrgMatch && bestLocScore < 0.5 {
		// Check both bio (headline) and title field for tech indicators
		title := ""
		if guessed.Fields != nil {
			title = guessed.Fields["title"]
		}
		if !hasTechTitle(guessed.Bio) && !hasTechTitle(title) {
			// Reduce score significantly - name alone is not enough for non-tech LinkedIn profiles
			score *= 0.4
			matches = append(matches, "penalty:non-tech-title")
		}
	}

	// Deduplicate match reasons
	seen := make(map[string]bool)
	var uniqueMatches []string
	for _, s := range matches {
		if !seen[s] {
			seen[s] = true
			uniqueMatches = append(uniqueMatches, s)
		}
	}

	return score, uniqueMatches
}

func hasLinkTo(from, to *profile.Profile) bool {
	toNorm := normalizeURL(to.URL)

	// Check social links
	for _, link := range from.SocialLinks {
		if normalizeURL(link) == toNorm {
			return true
		}
	}

	// Check website
	if from.Website != "" && normalizeURL(from.Website) == toNorm {
		return true
	}

	// Check fields
	for _, v := range from.Fields {
		if strings.HasPrefix(v, "http") && normalizeURL(v) == toNorm {
			return true
		}
	}

	return false
}

func scoreName(a, b string) float64 {
	if a == "" || b == "" {
		return 0
	}

	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))

	// Exact match
	if a == b {
		return 1.0
	}

	// One contains the other
	if strings.Contains(a, b) || strings.Contains(b, a) {
		return 0.7
	}

	// Check word overlap
	wordsA := strings.Fields(a)
	wordsB := strings.Fields(b)

	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}

	var overlap int
	var firstNameMatch bool
	for i, wa := range wordsA {
		for j, wb := range wordsB {
			if wa == wb || strings.Contains(wa, wb) || strings.Contains(wb, wa) {
				overlap++
				// Track if first word (likely first name) matches
				if i == 0 && j == 0 {
					firstNameMatch = true
				}
				break
			}
		}
	}

	if overlap > 0 {
		maxLen := max(len(wordsA), len(wordsB))
		score := float64(overlap) / float64(maxLen)

		// Penalize if first names don't match (likely different people)
		// Sharing just a surname shouldn't give high confidence
		if !firstNameMatch && overlap == 1 {
			// Only surname matches - give very low score
			score *= 0.2
		}

		return score
	}

	return 0
}

func scoreLocation(a, b string) float64 {
	if a == "" || b == "" {
		return 0
	}

	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))

	// Exact match
	if a == b {
		return 1.0
	}

	// One contains the other (e.g., "San Francisco" contains "San Francisco, CA")
	if strings.Contains(a, b) || strings.Contains(b, a) {
		return 0.8
	}

	// Check word overlap (city/state/country names)
	wordsA := strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == ' ' })
	wordsB := strings.FieldsFunc(b, func(r rune) bool { return r == ',' || r == ' ' })

	var overlap int
	for _, wa := range wordsA {
		wa = strings.TrimSpace(wa)
		if len(wa) < 2 {
			continue
		}
		for _, wb := range wordsB {
			wb = strings.TrimSpace(wb)
			if wa == wb {
				overlap++
				break
			}
		}
	}

	if overlap > 0 {
		return float64(overlap) / float64(max(len(wordsA), len(wordsB)))
	}

	return 0
}

func scoreBioOverlap(a, b string) float64 {
	if a == "" || b == "" {
		return 0
	}

	a = strings.ToLower(a)
	b = strings.ToLower(b)

	wordsA := extractSignificantWords(a)
	wordsB := extractSignificantWords(b)

	if len(wordsA) == 0 || len(wordsB) == 0 {
		return 0
	}

	var overlap int
	for _, wa := range wordsA {
		if slices.Contains(wordsB, wa) {
			overlap++
		}
	}

	if overlap >= 2 {
		return float64(overlap) / float64(max(len(wordsA), len(wordsB)))
	}

	return 0
}

// extractSignificantWords filters out common/short words.
func extractSignificantWords(s string) []string {
	commonWords := map[string]bool{
		"the": true, "a": true, "an": true, "and": true, "or": true, "but": true,
		"in": true, "on": true, "at": true, "to": true, "for": true, "of": true,
		"with": true, "by": true, "from": true, "as": true, "is": true, "was": true,
		"are": true, "been": true, "be": true, "have": true, "has": true, "had": true,
		"do": true, "does": true, "did": true, "will": true, "would": true, "could": true,
		"should": true, "may": true, "might": true, "must": true, "can": true,
		"i": true, "me": true, "my": true, "we": true, "our": true, "you": true, "your": true,
		"he": true, "she": true, "it": true, "they": true, "them": true, "their": true,
		"this": true, "that": true, "these": true, "those": true,
	}

	var words []string
	for w := range strings.FieldsSeq(s) {
		w = strings.Trim(w, ".,!?;:\"'()[]{}|/\\")
		w = strings.ToLower(w)
		if len(w) >= 3 && !commonWords[w] {
			words = append(words, w)
		}
	}
	return words
}

// extractOrganizationList parses organization names from Fields["organizations"].
// It normalizes organization names by removing common suffixes like "-dev", "-org", etc.
func extractOrganizationList(fields map[string]string) []string {
	if fields == nil {
		return nil
	}

	orgsStr, ok := fields["organizations"]
	if !ok || orgsStr == "" {
		return nil
	}

	// Split by comma (GitHub stores as "org1, org2, org3")
	parts := strings.Split(orgsStr, ",")
	var normalized []string

	for _, org := range parts {
		org = strings.TrimSpace(org)
		if org == "" {
			continue
		}

		// Normalize: remove common suffixes
		orgLower := strings.ToLower(org)
		orgLower = strings.TrimSuffix(orgLower, "-dev")
		orgLower = strings.TrimSuffix(orgLower, "-org")
		orgLower = strings.TrimSuffix(orgLower, "-io")
		orgLower = strings.TrimSuffix(orgLower, "-labs")

		normalized = append(normalized, orgLower)
	}

	return normalized
}

// getEmployer extracts employer/company from Fields.
func getEmployer(fields map[string]string) string {
	if fields == nil {
		return ""
	}

	// Check both "employer" and "company" keys
	if emp := fields["employer"]; emp != "" {
		return emp
	}
	if comp := fields["company"]; comp != "" {
		return comp
	}

	return ""
}

// isComplexSlug returns true if the slug has characteristics that make it more unique,
// such as containing digits, suffixes like "-dev", or being unusually long.
func isComplexSlug(slug string) bool {
	// Check for digits (e.g., "john123", "m4x4ll4n")
	for _, c := range slug {
		if c >= '0' && c <= '9' {
			return true
		}
	}

	// Check for common dev/tech suffixes that indicate intentional username choice
	techSuffixes := []string{"-dev", "-cgr", "-eng", "-tech", "-code", "-io", "-labs"}
	slugLower := strings.ToLower(slug)
	for _, suffix := range techSuffixes {
		if strings.HasSuffix(slugLower, suffix) {
			return true
		}
	}

	// Long slugs with 3+ parts are more unique (e.g., "john-david-smith")
	parts := strings.Split(slug, "-")
	return len(parts) >= 3
}

// hasTechTitle returns true if the bio/headline contains a job title that suggests
// the person is likely to use GitHub (developer, engineer, etc.).
func hasTechTitle(bio string) bool {
	if bio == "" {
		return false
	}

	bioLower := strings.ToLower(bio)

	// Tech-related job titles/keywords that suggest GitHub usage
	// These are checked as whole words or at word boundaries to avoid false matches
	techTerms := []string{
		"engineer", "developer", "programmer", "architect",
		"devops", "sre", "software", "backend", "frontend", "full-stack", "fullstack",
		"data scientist", "machine learning", "ml engineer",
		"security", "infosec", "devsecops", "appsec",
		"open source", "open-source", "maintainer", "creator",
		"cloud engineer", "platform engineer", "infrastructure",
		"vp engineering", "vp of engineering", "head of engineering", "head of r&d",
		"tech lead", "technical lead", "staff engineer", "principal engineer",
		"founding engineer", "co-founder", "founder",
		"researcher", // often technical
		"hacker", "maker",
		"kubernetes", "docker",
		"golang", "python developer", "rust developer", "java developer",
		"customer success", "technical support", // tech company roles
	}

	for _, term := range techTerms {
		if strings.Contains(bioLower, term) {
			return true
		}
	}

	// Check for standalone acronyms/titles that need word boundary matching
	// to avoid matching substrings (e.g., "cto" in "director")
	standaloneTerms := []string{"cto", "ceo", "cio", "aws", "gcp", "azure", "oss", "ai"}
	isWordChar := func(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') }
	words := strings.FieldsFunc(bioLower, func(r rune) bool { return !isWordChar(r) })
	wordSet := make(map[string]bool)
	for _, w := range words {
		wordSet[w] = true
	}
	for _, term := range standaloneTerms {
		if wordSet[term] {
			return true
		}
	}

	// Check for known tech companies - if they work at these, they likely use GitHub
	techCompanies := []string{
		"chainguard", "google", "microsoft", "amazon", "meta", "apple", "netflix",
		"github", "gitlab", "docker", "hashicorp", "datadog", "cloudflare",
		"vercel", "supabase", "prisma", "stripe", "twilio", "okta",
		"red hat", "canonical", "suse", "vmware", "nvidia", "intel", "amd",
		"isovalent", "cilium", "tigera", "solo.io", "tetrate",
		"kubernetes", "linux foundation", "cncf",
	}
	for _, company := range techCompanies {
		if strings.Contains(bioLower, company) {
			return true
		}
	}

	return false
}

// scoreOrganizationMatch checks if any organization name appears in bio, employer, or unstructured text.
// Organizations are already normalized (lowercase, suffixes removed).
func scoreOrganizationMatch(orgs []string, bio string, employer string, unstructured string) bool {
	if len(orgs) == 0 {
		return false
	}

	// Combine bio, employer, and unstructured text for searching
	searchText := strings.ToLower(bio + " " + employer + " " + unstructured)

	for _, org := range orgs {
		// Organization names are already lowercase and normalized
		if strings.Contains(searchText, org) {
			return true
		}
	}

	return false
}

// postsText extracts all text content from a profile's Posts slice.
func postsText(p *profile.Profile) string {
	if len(p.Posts) == 0 {
		return ""
	}
	var parts []string
	for _, post := range p.Posts {
		if post.Title != "" {
			parts = append(parts, post.Title)
		}
		if post.Content != "" {
			parts = append(parts, post.Content)
		}
	}
	return strings.Join(parts, " ")
}

// scoreInterestMatch checks if profiles share common interests.
// This catches cases like:
// - Reddit subreddit "vim" matching GitHub bio "Vim plugin artist".
// - Medium bio "I wrote a lot of Vim pumpkins" matching GitHub bio "Vim plugin artist".
// - Subreddits matching GitHub organizations (e.g., r/kubernetes + kubernetes org).
func scoreInterestMatch(a, b *profile.Profile) bool {
	// Extract interests from both profiles
	interestsA := extractInterests(a)
	interestsB := extractInterests(b)

	if len(interestsA) == 0 || len(interestsB) == 0 {
		return false
	}

	// Check for overlap - any shared interest is a match
	for interest := range interestsA {
		if interestsB[interest] {
			return true
		}
	}

	return false
}

// extractInterests extracts interest keywords from a profile.
// Sources: bio, subreddits (Reddit), organizations (GitHub), unstructured content.
func extractInterests(p *profile.Profile) map[string]bool {
	interests := make(map[string]bool)

	// Extract from subreddits (Reddit profiles store these in Fields)
	if p.Fields != nil {
		if subs := p.Fields["subreddits"]; subs != "" {
			for sub := range strings.SplitSeq(subs, ",") {
				sub = strings.TrimSpace(strings.ToLower(sub))
				if sub != "" && len(sub) >= 2 {
					interests[sub] = true
				}
			}
		}

		// Extract from GitHub organizations
		if orgs := p.Fields["organizations"]; orgs != "" {
			for org := range strings.SplitSeq(orgs, ",") {
				org = strings.TrimSpace(strings.ToLower(org))
				// Normalize org names (remove common suffixes)
				org = strings.TrimSuffix(org, "-dev")
				org = strings.TrimSuffix(org, "-org")
				org = strings.TrimSuffix(org, "-io")
				org = strings.TrimSuffix(org, "-labs")
				if org != "" && len(org) >= 2 {
					interests[org] = true
				}
			}
		}
	}

	// Extract interest keywords from bio
	bioInterests := extractInterestKeywords(p.Bio)
	maps.Copy(interests, bioInterests)

	// Extract from unstructured content (fallback for generic pages)
	if p.Unstructured != "" {
		unstructuredInterests := extractInterestKeywords(p.Unstructured)
		maps.Copy(interests, unstructuredInterests)
	}

	// Extract from structured posts (Reddit comments, YouTube videos, etc.)
	for _, post := range p.Posts {
		if post.Title != "" {
			titleInterests := extractInterestKeywords(post.Title)
			maps.Copy(interests, titleInterests)
		}
		if post.Content != "" {
			contentInterests := extractInterestKeywords(post.Content)
			maps.Copy(interests, contentInterests)
		}
	}

	return interests
}

// extractInterestKeywords extracts technology/interest keywords from text.
// These are specific enough to be meaningful signals when matched across profiles.
func extractInterestKeywords(text string) map[string]bool {
	if text == "" {
		return nil
	}

	interests := make(map[string]bool)
	textLower := strings.ToLower(text)

	// Technology/tool keywords that are specific enough to be meaningful
	// These should match subreddit names and common GitHub topics
	techKeywords := []string{
		// Editors
		"vim", "neovim", "emacs", "vscode",
		// Languages
		"golang", "rust", "python", "javascript", "typescript", "ruby", "elixir", "haskell", "scala", "kotlin", "swift",
		// Infrastructure
		"kubernetes", "docker", "terraform", "ansible", "linux", "nixos", "homelab",
		// Frameworks
		"react", "vue", "angular", "django", "rails", "flask", "nextjs",
		// Security
		"infosec", "security", "cryptography", "malware",
		// DevOps/Cloud
		"devops", "aws", "azure", "gcp", "cloudflare",
		// Data
		"machinelearning", "datascience", "postgres", "mysql", "redis", "elasticsearch",
		// Mobile
		"ios", "android", "flutter", "reactnative",
		// Other tech
		"git", "github", "gitlab", "opensource",
	}

	for _, kw := range techKeywords {
		if strings.Contains(textLower, kw) {
			interests[kw] = true
		}
	}

	// Also check for specific patterns like "X plugin" or "X developer"
	// to catch things like "vim plugin artist"
	for _, kw := range techKeywords {
		patterns := []string{
			kw + " plugin",
			kw + " developer",
			kw + " engineer",
			kw + " maintainer",
		}
		for _, pattern := range patterns {
			if strings.Contains(textLower, pattern) {
				interests[kw] = true
			}
		}
	}

	return interests
}
