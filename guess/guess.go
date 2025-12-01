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
	knownPlatforms := make(map[string]bool)      // Platforms we have profiles for (guessed or vouched)
	vouchedPlatforms := make(map[string]bool)    // Platforms from vouched sources only
	for _, p := range known {
		knownURLs[normalizeURL(p.URL)] = true
		knownPlatforms[p.Platform] = true
		vouchedPlatforms[p.Platform] = true
		// Also mark platforms from social links as vouched - these are verified URLs
		// that we'll fetch directly, so no need to guess for these platforms
		for _, link := range p.SocialLinks {
			knownURLs[normalizeURL(link)] = true
			if cfg.PlatformDetector != nil {
				if platform := cfg.PlatformDetector(link); platform != "" && platform != "generic" {
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
					if linkPlatform != "" && linkPlatform != "generic" && knownPlatforms[linkPlatform] {
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
						cfg.Logger.Debug("social link fetch failed", "url", url, "error", err)
						return
					}

					// Score against ALL known profiles (original + first round guesses)
					allKnown := append(known, guessed...)
					confidence, matches := scoreMatch(p, allKnown, candidateURL{
						url:       url,
						username:  p.Username,
						platform:  p.Platform,
						matchType: "linked", // This is a verified link
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

	return guessed
}

// filterHighestConfidencePerPlatform keeps only the highest confidence profile(s) per platform.
// If multiple profiles are tied at the highest confidence, all are kept.
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

	// Keep only profiles at max confidence for their platform
	var result []*profile.Profile
	for platform, platformProfiles := range byPlatform {
		maxConf := maxConfidence[platform]
		for _, p := range platformProfiles {
			if p.Confidence == maxConf {
				result = append(result, p)
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

func generateCandidates(usernames []string, names []string, knownURLs map[string]bool, knownPlatforms map[string]bool, vouchedPlatforms map[string]bool) []candidateURL {
	var candidates []candidateURL

	// Generate username-based candidates
	for _, username := range usernames {
		// Add platform patterns
		for _, pp := range platformPatterns {
			// Skip platforms we already have a verified profile for
			if knownPlatforms[pp.name] {
				continue
			}

			// Skip LinkedIn for usernames with underscores (LinkedIn only allows hyphens)
			if pp.name == "linkedin" && strings.Contains(username, "_") {
				continue
			}

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

	// Generate name-based LinkedIn candidates only if we don't have a vouched LinkedIn profile
	// Username-based guesses may find wrong people (common usernames), so we still try
	// name-based guessing. But if we have a vouched LinkedIn from a trusted source, skip.
	if vouchedPlatforms["linkedin"] {
		return candidates
	}
	for _, name := range names {
		slug := slugifyName(name)
		if slug == "" || len(slug) < 3 {
			continue
		}

		// Try hyphenated version (e.g., dan-lorenc)
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

		// Also try without hyphens (e.g., danlorenc)
		slugNoHyphens := strings.ReplaceAll(slug, "-", "")
		if slugNoHyphens != slug && len(slugNoHyphens) >= 3 {
			urlNoHyphens := "https://www.linkedin.com/in/" + slugNoHyphens + "/"
			if !knownURLs[normalizeURL(urlNoHyphens)] {
				candidates = append(candidates, candidateURL{
					url:        urlNoHyphens,
					username:   slugNoHyphens,
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
	// Normalize Mastodon web interface URLs to canonical profile URLs
	// e.g., triangletoot.party/web/@username -> triangletoot.party/@username
	url = strings.Replace(url, "/web/@", "/@", 1)
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
	var hasWebsiteMatch, hasEmployerMatch, hasOrgMatch bool

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

		// Check organization match (GitHub organizations vs bio/employer/unstructured mentions)
		if !hasOrgMatch {
			// Get organizations from either profile (usually GitHub)
			guessedOrgs := extractOrganizationList(guessed.Fields)
			knownOrgs := extractOrganizationList(k.Fields)

			// Check if any organization appears in the other profile's bio, employer, or unstructured text
			if len(guessedOrgs) > 0 || len(knownOrgs) > 0 {
				// Check guessed orgs against known bio/employer/unstructured
				if len(guessedOrgs) > 0 && scoreOrganizationMatch(guessedOrgs, k.Bio, getEmployer(k.Fields), k.Unstructured) {
					hasOrgMatch = true
					matches = append(matches, "organization:"+k.Platform)
				}
				// Check known orgs against guessed bio/employer/unstructured
				if !hasOrgMatch && len(knownOrgs) > 0 && scoreOrganizationMatch(knownOrgs, guessed.Bio, getEmployer(guessed.Fields), guessed.Unstructured) {
					hasOrgMatch = true
					matches = append(matches, "organization:"+k.Platform)
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
							matches = append(matches, "organization:"+k.Platform)
							break
						}
					}
				}
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
		maxLen := len(wordsA)
		if len(wordsB) > maxLen {
			maxLen = len(wordsB)
		}
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
		maxLen := len(wordsA)
		if len(wordsB) > maxLen {
			maxLen = len(wordsB)
		}
		return float64(overlap) / float64(maxLen)
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
		maxLen := len(wordsA)
		if len(wordsB) > maxLen {
			maxLen = len(wordsB)
		}
		return float64(overlap) / float64(maxLen)
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
	if len(parts) >= 3 {
		return true
	}

	return false
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
	words := strings.FieldsFunc(bioLower, func(r rune) bool {
		return !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
	})
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
