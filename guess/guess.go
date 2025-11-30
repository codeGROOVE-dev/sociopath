// Package guess discovers related social media profiles based on known usernames.
package guess

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/codeGROOVE-dev/sociopath/profile"
)

// Fetcher is a function that fetches a profile from a URL.
type Fetcher func(ctx context.Context, url string) (*profile.Profile, error)

// Config holds configuration for guessing.
type Config struct {
	Logger  *slog.Logger
	Fetcher Fetcher
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
var platformPatterns = []struct {
	name    string
	pattern string // %s will be replaced with username
}{
	{"bluesky", "https://bsky.app/profile/%s.bsky.social"},
	{"twitter", "https://twitter.com/%s"},
	{"github", "https://github.com/%s"},
	{"devto", "https://dev.to/%s"},
	{"instagram", "https://instagram.com/%s"},
	{"tiktok", "https://tiktok.com/@%s"},
	{"linkedin", "https://linkedin.com/in/%s"},
}

// Related discovers related profiles based on known profiles.
// It extracts usernames and tries to find matching profiles on other platforms.
func Related(ctx context.Context, known []*profile.Profile, cfg Config) []*profile.Profile {
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	// Extract all known usernames
	usernames := extractUsernames(known)
	cfg.Logger.Debug("extracted usernames for guessing", "count", len(usernames))

	// Build set of already known URLs to avoid duplicates
	knownURLs := make(map[string]bool)
	for _, p := range known {
		knownURLs[normalizeURL(p.URL)] = true
	}

	// Generate candidate URLs
	candidates := generateCandidates(usernames, knownURLs)
	cfg.Logger.Info("generated guess candidates", "count", len(candidates))

	// Fetch candidates concurrently with rate limiting
	var guessed []*profile.Profile
	var mu sync.Mutex
	sem := make(chan struct{}, 5) // Max 5 concurrent requests
	var wg sync.WaitGroup

	for _, c := range candidates {
		if ctx.Err() != nil {
			break
		}

		wg.Add(1)
		go func(candidate candidateURL) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			cfg.Logger.Debug("trying guess candidate", "url", candidate.url, "username", candidate.username)

			p, err := cfg.Fetcher(fetchCtx, candidate.url)
			if err != nil {
				cfg.Logger.Debug("guess candidate failed", "url", candidate.url, "error", err)
				return
			}

			// Score the match against known profiles
			confidence, matches := scoreMatch(p, known, candidate.username)
			if confidence < 0.3 {
				cfg.Logger.Debug("guess candidate low confidence, skipping", "url", candidate.url, "confidence", confidence)
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
	return guessed
}

type candidateURL struct {
	url      string
	username string
	platform string
}

func extractUsernames(profiles []*profile.Profile) []string {
	seen := make(map[string]bool)
	var usernames []string

	for _, p := range profiles {
		// Extract username from profile (only from recognized social platforms)
		if p.Username != "" && isSocialPlatform(p.Platform) {
			u := strings.ToLower(p.Username)
			if isValidUsername(u) && !seen[u] {
				seen[u] = true
				usernames = append(usernames, u)
			}
		}

		// Extract username from URL path (only for social platforms)
		if isSocialPlatform(p.Platform) {
			if u := extractUsernameFromURL(p.URL); u != "" {
				u = strings.ToLower(u)
				if isValidUsername(u) && !seen[u] {
					seen[u] = true
					usernames = append(usernames, u)
				}
			}
		}
	}

	return usernames
}

func isSocialPlatform(platform string) bool {
	social := map[string]bool{
		"github": true, "twitter": true, "mastodon": true, "bluesky": true,
		"linkedin": true, "instagram": true, "tiktok": true, "devto": true,
		"stackoverflow": true, "linktree": true,
	}
	return social[strings.ToLower(platform)]
}

func isValidUsername(u string) bool {
	// Skip very short usernames (too generic)
	if len(u) < 3 {
		return false
	}

	// Skip common non-username strings
	invalid := map[string]bool{
		"users": true, "user": true, "profile": true, "settings": true,
		"about": true, "help": true, "terms": true, "privacy": true,
		"home": true, "index": true, "search": true, "login": true,
		"logout": true, "signup": true, "register": true, "api": true,
	}
	return !invalid[u]
}

func extractUsernameFromURL(url string) string {
	// Remove protocol and domain
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")

	parts := strings.Split(url, "/")
	if len(parts) < 2 {
		return ""
	}

	// Common path segments to skip
	skipPaths := map[string]bool{
		"in": true, "profile": true, "users": true, "user": true,
		"p": true, "u": true, "status": true, "posts": true,
	}

	// Handle @username patterns
	for _, part := range parts[1:] {
		part = strings.TrimPrefix(part, "@")
		part = strings.Split(part, "?")[0] // Remove query string
		part = strings.TrimSpace(part)

		if part == "" || skipPaths[strings.ToLower(part)] {
			continue
		}

		// Skip if it looks like a numeric ID
		if isNumeric(part) {
			continue
		}

		return part
	}

	return ""
}

func isNumeric(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return s != ""
}

func generateCandidates(usernames []string, knownURLs map[string]bool) []candidateURL {
	var candidates []candidateURL

	for _, username := range usernames {
		// Add platform patterns
		for _, pp := range platformPatterns {
			url := strings.Replace(pp.pattern, "%s", username, 1)
			if !knownURLs[normalizeURL(url)] {
				candidates = append(candidates, candidateURL{
					url:      url,
					username: username,
					platform: pp.name,
				})
			}
		}

		// Add Mastodon servers
		for _, server := range mastodonServers {
			url := "https://" + server + "/@" + username
			if !knownURLs[normalizeURL(url)] {
				candidates = append(candidates, candidateURL{
					url:      url,
					username: username,
					platform: "mastodon",
				})
			}
		}
	}

	return candidates
}

func normalizeURL(url string) string {
	url = strings.TrimSuffix(url, "/")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "www.")
	return strings.ToLower(url)
}

// scoreMatch calculates confidence that a guessed profile belongs to the same person.
// Returns confidence (0.0-1.0) and list of matching criteria.
func scoreMatch(guessed *profile.Profile, known []*profile.Profile, targetUsername string) (confidence float64, matchReasons []string) {
	var score float64
	var matches []string

	// Check username match (base match since we guessed based on username)
	guessedUser := strings.ToLower(guessed.Username)
	if guessedUser == targetUsername {
		score += 0.3
		matches = append(matches, "username:exact")
	} else if strings.Contains(guessedUser, targetUsername) || strings.Contains(targetUsername, guessedUser) {
		score += 0.2
		matches = append(matches, "username:substring")
	}

	// Check against each known profile for additional signals
	for _, k := range known {
		// Check for links between profiles (highest signal)
		if hasLinkTo(guessed, k) || hasLinkTo(k, guessed) {
			score += 0.5
			matches = append(matches, "linked:"+k.Platform)
		}

		// Check name similarity (high signal)
		if nameScore := scoreName(guessed.Name, k.Name); nameScore > 0 {
			score += nameScore * 0.3
			matches = append(matches, "name:"+k.Platform)
		}

		// Check location match (medium signal)
		if locScore := scoreLocation(guessed.Location, k.Location); locScore > 0 {
			score += locScore * 0.15
			matches = append(matches, "location:"+k.Platform)
		}

		// Check bio word overlap (lower signal)
		if bioScore := scoreBioOverlap(guessed.Bio, k.Bio); bioScore > 0 {
			score += bioScore * 0.1
			matches = append(matches, "bio:"+k.Platform)
		}

		// Check website match (high signal)
		if guessed.Website != "" && k.Website != "" {
			if normalizeURL(guessed.Website) == normalizeURL(k.Website) {
				score += 0.4
				matches = append(matches, "website:"+k.Platform)
			}
		}
	}

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
	}

	return score, dedupe(matches)
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
	for _, wa := range wordsA {
		for _, wb := range wordsB {
			if wa == wb || strings.Contains(wa, wb) || strings.Contains(wb, wa) {
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
		for _, wb := range wordsB {
			if wa == wb {
				overlap++
				break
			}
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
	for _, w := range strings.Fields(s) {
		w = strings.Trim(w, ".,!?;:\"'()[]{}|/\\")
		w = strings.ToLower(w)
		if len(w) >= 3 && !commonWords[w] {
			words = append(words, w)
		}
	}
	return words
}

func dedupe(strs []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, s := range strs {
		if !seen[s] {
			seen[s] = true
			result = append(result, s)
		}
	}
	return result
}
