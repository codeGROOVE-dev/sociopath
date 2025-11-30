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
	{"weibo", "https://weibo.com/%s"},
	{"zhihu", "https://zhihu.com/people/%s"},
	{"bilibili", "https://space.bilibili.com/%s"},
	{"reddit", "https://reddit.com/user/%s"},
	{"youtube", "https://youtube.com/@%s"},
	{"medium", "https://medium.com/@%s"},
	{"habr", "https://habr.com/users/%s"},
	{"vkontakte", "https://vk.com/%s"},
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

	// Extract names for LinkedIn slug guessing
	names := extractNames(known)
	cfg.Logger.Debug("extracted names for guessing", "count", len(names))

	// Build set of already known URLs to avoid duplicates
	knownURLs := make(map[string]bool)
	knownPlatforms := make(map[string]bool)
	for _, p := range known {
		knownURLs[normalizeURL(p.URL)] = true
		knownPlatforms[p.Platform] = true
	}

	// Generate candidate URLs
	candidates := generateCandidates(usernames, names, knownURLs, knownPlatforms)
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
				cfg.Logger.Debug("guess candidate failed", "url", candidate.url, "error", err)
				return
			}

			// Score the match against known profiles
			confidence, matches := scoreMatch(p, known, candidate)
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

	// Second round: Fetch social links and extract usernames from guessed profiles
	// This handles cases like finding "thomrstrom" from a Mastodon link in a GitHub profile
	if len(guessed) > 0 {
		// First, collect all social links from guessed profiles to fetch directly
		var socialLinksToFetch []string
		for _, p := range guessed {
			for _, link := range p.SocialLinks {
				normalized := normalizeURL(link)
				if !knownURLs[normalized] {
					socialLinksToFetch = append(socialLinksToFetch, link)
					knownURLs[normalized] = true  // Mark as known immediately
				}
			}
			// Also check website field
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
						cfg.Logger.Debug("social link fetch failed", "url", url, "error", err)
						return
					}

					// Score against ALL known profiles (original + first round guesses)
					allKnown := append(known, guessed...)
					confidence, matches := scoreMatch(p, allKnown, candidateURL{
						url:       url,
						username:  p.Username,
						platform:  p.Platform,
						matchType: "linked",  // This is a verified link
					})

					// Lower threshold for linked profiles since they were directly referenced
					if confidence < 0.25 {
						cfg.Logger.Debug("social link low confidence, skipping",
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
		secondRoundUsernames := extractUsernames(guessed)
		secondRoundNames := extractNames(guessed)

		// Only generate candidates for NEW usernames/names not already tried
		newUsernames := make([]string, 0)
		for _, u := range secondRoundUsernames {
			alreadyTried := false
			for _, orig := range usernames {
				if u == orig {
					alreadyTried = true
					break
				}
			}
			if !alreadyTried {
				newUsernames = append(newUsernames, u)
			}
		}

		newNames := make([]string, 0)
		for _, n := range secondRoundNames {
			alreadyTried := false
			for _, orig := range names {
				if n == orig {
					alreadyTried = true
					break
				}
			}
			if !alreadyTried {
				newNames = append(newNames, n)
			}
		}

		if len(newUsernames) > 0 || len(newNames) > 0 {
			cfg.Logger.Debug("second round: found new usernames from guessed profiles",
				"new_usernames", len(newUsernames), "new_names", len(newNames))

			secondCandidates := generateCandidates(newUsernames, newNames, knownURLs, knownPlatforms)
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
						cfg.Logger.Debug("second round candidate failed", "url", candidate.url, "error", err)
						return
					}

					// Score against ALL known profiles (original + first round guesses)
					allKnown := append(known, guessed...)
					confidence, matches := scoreMatch(p, allKnown, candidate)
					if confidence < 0.3 {
						cfg.Logger.Debug("second round candidate low confidence, skipping",
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

	return guessed
}

type candidateURL struct {
	url        string
	username   string
	platform   string
	matchType  string // "username" or "name"
	sourceName string // for name-based matches, store the original name
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
		"generic": true, // generic websites don't have meaningful usernames
	}
	return !nonSocial[strings.ToLower(platform)]
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

func generateCandidates(usernames []string, names []string, knownURLs map[string]bool, knownPlatforms map[string]bool) []candidateURL {
	var candidates []candidateURL

	// Generate username-based candidates
	for _, username := range usernames {
		// Add platform patterns
		for _, pp := range platformPatterns {
			url := strings.Replace(pp.pattern, "%s", username, 1)
			if !knownURLs[normalizeURL(url)] {
				candidates = append(candidates, candidateURL{
					url:       url,
					username:  username,
					platform:  pp.name,
					matchType: "username",
				})
			}
		}

		// Add Mastodon servers only if we don't already have a Mastodon profile
		if !knownPlatforms["mastodon"] {
			for _, server := range mastodonServers {
				url := "https://" + server + "/@" + username
				if !knownURLs[normalizeURL(url)] {
					candidates = append(candidates, candidateURL{
						url:       url,
						username:  username,
						platform:  "mastodon",
						matchType: "username",
					})
				}
			}
		}
	}

	// Generate name-based LinkedIn candidates
	if !knownPlatforms["linkedin"] {
		for _, name := range names {
			slug := slugifyName(name)
			if slug == "" || len(slug) < 3 {
				continue
			}

			url := "https://www.linkedin.com/in/" + slug + "/"
			if !knownURLs[normalizeURL(url)] {
				candidates = append(candidates, candidateURL{
					url:        url,
					username:   slug,
					platform:   "linkedin",
					matchType:  "name",
					sourceName: name,
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
	url = strings.ToLower(url)
	// Normalize x.com to twitter.com (they're the same platform)
	url = strings.Replace(url, "x.com/", "twitter.com/", 1)
	return url
}

// scoreMatch calculates confidence that a guessed profile belongs to the same person.
// Returns confidence (0.0-1.0) and list of matching criteria.
func scoreMatch(guessed *profile.Profile, known []*profile.Profile, candidate candidateURL) (confidence float64, matchReasons []string) {
	var score float64
	var matches []string

	targetUsername := candidate.username
	matchType := candidate.matchType

	// Base score depends on match type
	if matchType == "name" {
		// Name-based matches get slightly lower base confidence than username matches
		score += 0.25
		matches = append(matches, "name:slug")
	} else {
		// Username match scoring
		guessedUser := strings.ToLower(guessed.Username)

		// Check if username has digits (more unique)
		hasDigits := false
		for _, c := range targetUsername {
			if c >= '0' && c <= '9' {
				hasDigits = true
				break
			}
		}

		// Username match scoring - lower confidence for short usernames without digits
		if guessedUser == targetUsername {
			if len(targetUsername) < 6 && !hasDigits {
				// Short username without digits gets minimal base score
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
	var hasWebsiteMatch, hasEmployerMatch bool

	// Check against each known profile for additional signals
	for _, k := range known {
		// Check for links between profiles (highest signal)
		if hasLinkTo(guessed, k) || hasLinkTo(k, guessed) {
			if !hasLink {
				hasLink = true
				matches = append(matches, "linked:"+k.Platform)
			}
		}

		// Check name similarity (high signal) - track best score
		if nameScore := scoreName(guessed.Name, k.Name); nameScore > bestNameScore {
			if bestNameScore == 0 {
				matches = append(matches, "name:"+k.Platform)
			}
			bestNameScore = nameScore
		}

		// Check location match (medium signal) - track best score
		if locScore := scoreLocation(guessed.Location, k.Location); locScore > bestLocScore {
			if bestLocScore == 0 {
				matches = append(matches, "location:"+k.Platform)
			}
			bestLocScore = locScore
		}

		// Check bio word overlap (lower signal) - track best score
		if bioScore := scoreBioOverlap(guessed.Bio, k.Bio); bioScore > bestBioScore {
			if bestBioScore == 0 {
				matches = append(matches, "bio:"+k.Platform)
			}
			bestBioScore = bioScore
		}

		// Check website match (high signal)
		if guessed.Website != "" && k.Website != "" {
			if normalizeURL(guessed.Website) == normalizeURL(k.Website) {
				if !hasWebsiteMatch {
					hasWebsiteMatch = true
					matches = append(matches, "website:"+k.Platform)
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
			if k.Fields != nil {
				if emp := k.Fields["employer"]; emp != "" {
					knownEmployer = strings.ToLower(strings.TrimSpace(emp))
				} else if comp := k.Fields["company"]; comp != "" {
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
					matches = append(matches, "employer:"+k.Platform)
				}
			}
		}
	}

	// Add best signals to score (only once, not per profile)
	if hasLink {
		score += 0.5
	}
	if bestNameScore > 0 {
		score += bestNameScore * 0.3
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

	// Cap at 1.0
	if score > 1.0 {
		score = 1.0
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
