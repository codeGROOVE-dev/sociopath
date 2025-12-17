package guess

import (
	"log/slog"
	"maps"
	"slices"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

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

// normalizeGroups normalizes group/organization names by removing common suffixes like "-dev", "-org", etc.
func normalizeGroups(groups []string) []string {
	if len(groups) == 0 {
		return nil
	}

	var normalized []string
	for _, org := range groups {
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
	if subs := p.Fields["subreddits"]; subs != "" {
		for sub := range strings.SplitSeq(subs, ",") {
			sub = strings.TrimSpace(strings.ToLower(sub))
			if sub != "" && len(sub) >= 2 {
				interests[sub] = true
			}
		}
	}

	// Extract from groups (GitHub organizations, etc.)
	for _, org := range p.Groups {
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

	// Extract interest keywords from bio
	bioInterests := extractInterestKeywords(p.Bio)
	maps.Copy(interests, bioInterests)

	// Extract from content (README, page content, etc.)
	if p.Content != "" {
		contentInterests := extractInterestKeywords(p.Content)
		maps.Copy(interests, contentInterests)
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

// boostCrossPlatformMatches increases confidence for guessed profiles when the same
// username is found on multiple platforms of the same type (e.g., GitHub and GitLab are both "code" platforms).
// Only boosts from a higher-confidence profile, capped at that source's confidence.
// Skips profiles with conflicting display names.
func boostCrossPlatformMatches(guessed, known []*profile.Profile, logger *slog.Logger) {
	// Index all profiles by platformType:username
	byKey := make(map[string][]*profile.Profile)
	for _, p := range slices.Concat(known, guessed) {
		pt := effectivePlatformType(p.Platform)
		if pt == profile.PlatformTypeOther || p.Username == "" {
			continue
		}
		k := string(pt) + ":" + strings.ToLower(p.Username)
		byKey[k] = append(byKey[k], p)
	}

	for _, p := range guessed {
		pt := effectivePlatformType(p.Platform)
		if pt == profile.PlatformTypeOther || p.Username == "" {
			continue
		}

		others := byKey[string(pt)+":"+strings.ToLower(p.Username)]
		if len(others) < 2 {
			continue
		}

		// Find best source: higher confidence, no name conflict
		var src *profile.Profile
		var locMatch, tzMatch bool
		for _, o := range others {
			if o.URL == p.URL || o.Confidence <= p.Confidence {
				continue
			}
			if p.DisplayName != "" && o.DisplayName != "" && scoreName(p.DisplayName, o.DisplayName) == 0 {
				logger.Debug("cross-platform boost skipped due to name mismatch",
					"url", p.URL, "source_url", o.URL,
					"name", p.DisplayName, "source_name", o.DisplayName)
				continue
			}
			if src == nil || o.Confidence > src.Confidence {
				src = o
			}
			if p.Location != "" && o.Location != "" && scoreLocation(p.Location, o.Location) > 0.5 {
				locMatch = true
			}
			if p.UTCOffset != nil && o.UTCOffset != nil && *p.UTCOffset == *o.UTCOffset {
				tzMatch = true
			}
		}
		if src == nil {
			continue
		}

		// 0.15 base + 0.10 each for location/timezone match, capped at source confidence
		bonus := 0.15
		if locMatch {
			bonus += 0.10
		}
		if tzMatch {
			bonus += 0.10
		}
		newConf := min(p.Confidence+bonus, src.Confidence)
		if newConf <= p.Confidence {
			continue
		}

		logger.Info("cross-platform boost",
			"url", p.URL, "username", p.Username, "platform_type", pt,
			"old_confidence", p.Confidence, "new_confidence", newConf,
			"source_url", src.URL, "source_confidence", src.Confidence,
			"loc_match", locMatch, "tz_match", tzMatch)

		p.Confidence = newConf
		p.GuessMatch = append(p.GuessMatch, "cross-platform:"+string(pt))
		if locMatch {
			p.GuessMatch = append(p.GuessMatch, "cross-platform:location")
		}
		if tzMatch {
			p.GuessMatch = append(p.GuessMatch, "cross-platform:timezone")
		}
	}
}

// effectivePlatformType returns the platform type for cross-platform matching.
// Package registries are treated as code platforms since they're closely related.
func effectivePlatformType(platform string) profile.PlatformType {
	pType := profile.TypeOf(platform)
	if pType == profile.PlatformTypePackage {
		return profile.PlatformTypeCode
	}
	return pType
}

// isSystemPage returns true if the URL is a system/info page on a recognized platform.
// We filter these out because they're site info pages, not user profiles.
// Personal websites are NOT filtered - their /about pages often contain user info.
func isSystemPage(urlStr string) bool {
	lower := strings.ToLower(urlStr)

	// Recognized social/platform domains where system pages should be filtered.
	platformDomains := []string{
		// Code hosting
		"github.com", "github.blog", "gitlab.com", "bitbucket.org", "codeberg.org", "gitee.com",
		// Social media
		"twitter.com", "x.com", "facebook.com", "instagram.com",
		"linkedin.com", "youtube.com", "tiktok.com", "twitch.tv",
		"reddit.com", "medium.com", "dev.to", "hashnode.com",
		// Package registries
		"npmjs.com", "pypi.org", "rubygems.org", "crates.io",
		"hub.docker.com", "huggingface.co", "hex.pm",
		// Q&A / Forums
		"stackoverflow.com", "stackexchange.com",
		"hackerone.com", "bugcrowd.com",
		// Identity / Social
		"keybase.io", "gravatar.com",
		"mastodon.social", "hachyderm.io", "fosstodon.org",
		"bsky.app", "vk.com", "weibo.com", "bilibili.com",
		"substack.com", "patreon.com", "ko-fi.com",
		"discord.com", "discordapp.com", "slack.com",
		"telegram.org", "t.me",
		// Coding challenges
		"leetcode.com", "codewars.com", "hackerrank.com",
		"exercism.org", "freecodecamp.org",
		// Design
		"dribbble.com", "behance.net", "codepen.io",
		// Music / Media
		"soundcloud.com", "spotify.com", "bandcamp.com",
		// Gaming
		"steam.com", "steamcommunity.com",
		// Programming languages and frameworks (their /about pages are site info, not user profiles)
		"scratch.mit.edu", "python.org", "golang.org", "go.dev", "rust-lang.org",
		"ruby-lang.org", "nodejs.org", "deno.land", "typescriptlang.org",
		"kotlinlang.org", "swift.org", "scala-lang.org", "elixir-lang.org",
		"haskell.org", "clojure.org", "erlang.org", "julialang.org",
		"r-project.org", "perl.org", "php.net", "lua.org",
		"reactjs.org", "react.dev", "vuejs.org", "angular.io", "svelte.dev",
		"nextjs.org", "nuxt.com", "astro.build", "remix.run",
		"djangoproject.com", "rubyonrails.org", "flask.palletsprojects.com",
		"spring.io", "laravel.com", "symfony.com",
		"kubernetes.io", "docker.com", "terraform.io", "ansible.com",
		"nginx.org", "apache.org", "linux.org", "kernel.org",
		"mozilla.org", "chromium.org", "webkit.org",
	}

	// Check if URL is on a recognized platform
	isPlatform := false
	for _, domain := range platformDomains {
		if strings.Contains(lower, domain) {
			isPlatform = true
			break
		}
	}

	// Only filter system pages on recognized platforms
	if !isPlatform {
		return false
	}

	// System page paths that are never user profiles
	systemPaths := []string{
		"/about", "/about-us", "/aboutus",
		"/contact", "/contact-us", "/contactus",
		"/help", "/support", "/faq",
		"/terms", "/tos", "/terms-of-service",
		"/privacy", "/privacy-policy",
		"/legal", "/dmca", "/copyright",
		"/press", "/media", "/newsroom",
		"/careers", "/jobs",
		"/blog", "/news",
		"/api", "/developers", "/docs",
		"/security", "/trust",
		"/cookies", "/cookie-policy",
		"/guidelines", "/rules", "/policies",
		"/accessibility",
		"/advertise", "/advertising", "/ads",
		"/partners", "/affiliates",
	}

	for _, sp := range systemPaths {
		if strings.HasSuffix(lower, sp) ||
			strings.Contains(lower, sp+"/") ||
			strings.Contains(lower, sp+"?") {
			return true
		}
	}

	return false
}
