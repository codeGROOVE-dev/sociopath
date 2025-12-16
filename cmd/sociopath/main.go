// Command sociopath fetches social media profiles from URLs.
//
// Usage:
//
//	sociopath https://mastodon.social/@johndoe
//	sociopath https://linkedin.com/in/johndoe  # requires LINKEDIN_* env vars
//	sociopath https://twitter.com/johndoe      # requires TWITTER_* env vars
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
	"github.com/codeGROOVE-dev/sociopath/pkg/sociopath"
)

// emailList is a flag.Value that collects multiple email addresses.
type emailList []string

func (e *emailList) String() string { return strings.Join(*e, ",") }
func (e *emailList) Set(v string) error {
	*e = append(*e, v)
	return nil
}

func main() {
	debug := flag.Bool("debug", false, "enable debug logging")
	verbose := flag.Bool("v", false, "verbose logging (same as -debug)")
	useBrowser := flag.Bool("browser", false, "enable reading cookies from browser stores (disabled by default)")
	noCache := flag.Bool("no-cache", false, "disable HTTP caching (enabled by default with 75-day TTL)")
	cacheTTL := flag.Duration("cache-ttl", 75*24*time.Hour, "cache time-to-live (default: 75 days, use 24h for testing)")
	recursive := flag.Bool("r", false, "recursively fetch social media profiles from discovered links")
	guessMode := flag.Bool("guess", false, "guess related profiles based on discovered usernames (implies -r)")
	jsonOutput := flag.Bool("json", false, "output as JSON (default: pretty format when stdout is a terminal)")
	prettyFlag := flag.Bool("pretty", false, "force pretty output even when stdout is not a terminal")
	var emails emailList
	flag.Var(&emails, "email", "email address to associate with profile (can be specified multiple times)")
	flag.Parse()

	// Determine output format: pretty for TTY or --pretty flag, JSON for pipes or --json
	prettyOutput := *prettyFlag || (!*jsonOutput && term.IsTerminal(int(os.Stdout.Fd())))

	// Allow --email without URL for email-only lookups
	if flag.NArg() < 1 && len(emails) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sociopath [options] <url>")
		fmt.Fprintln(os.Stderr, "       sociopath --email <address> [--email <address2>...]")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nSupported platforms:")
		fmt.Fprintln(os.Stderr, "  - LinkedIn (use --browser for auth)")
		fmt.Fprintln(os.Stderr, "  - Twitter/X (use --browser for auth)")
		fmt.Fprintln(os.Stderr, "  - Mastodon (no auth)")
		fmt.Fprintln(os.Stderr, "  - BlueSky (no auth)")
		fmt.Fprintln(os.Stderr, "  - Dev.to (no auth)")
		fmt.Fprintln(os.Stderr, "  - StackOverflow (no auth)")
		fmt.Fprintln(os.Stderr, "  - Linktree (no auth)")
		fmt.Fprintln(os.Stderr, "  - GitHub (no auth)")
		fmt.Fprintln(os.Stderr, "  - Google/Gmail (no auth, requires GAIA ID for full data)")
		fmt.Fprintln(os.Stderr, "  - Gravatar (no auth, any email)")
		fmt.Fprintln(os.Stderr, "  - Mail.ru (no auth)")
		fmt.Fprintln(os.Stderr, "  - Generic websites (no auth)")
		fmt.Fprintln(os.Stderr, "\nEmail lookup:")
		fmt.Fprintln(os.Stderr, "  Use --email alone to look up profiles via Gravatar, Mail.ru, etc.")
		fmt.Fprintln(os.Stderr, "  Use --email with a URL to associate emails with a fetched profile.")
		fmt.Fprintln(os.Stderr, "\nGuess mode:")
		fmt.Fprintln(os.Stderr, "  --guess tries to find related profiles on other platforms")
		fmt.Fprintln(os.Stderr, "  by checking if the same username exists. Guessed profiles")
		fmt.Fprintln(os.Stderr, "  include confidence scores based on matching signals.")
		os.Exit(1)
	}

	input := flag.Arg(0)

	// Setup logger
	logLevel := slog.LevelInfo
	if *debug || *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Setup cache
	var httpCache *httpcache.Cache
	if *noCache {
		httpCache = httpcache.NewNull()
		logger.Debug("HTTP cache disabled")
	} else {
		var err error
		httpCache, err = httpcache.New(*cacheTTL)
		if err != nil {
			logger.Warn("failed to initialize cache, falling back to null cache", "error", err)
			httpCache = httpcache.NewNull()
		} else {
			defer func() {
				if err := httpCache.Close(); err != nil {
					logger.Warn("failed to close cache", "error", err)
				}
			}()
			logger.Debug("HTTP cache initialized", "ttl", cacheTTL.String())
		}
	}
	// Output cache stats at end
	defer func() {
		stats := httpcache.CacheStats()
		total := stats.Hits + stats.Misses
		if total > 0 {
			hitRate := float64(stats.Hits) / float64(total) * 100
			logger.Info("cache stats", "hits", stats.Hits, "misses", stats.Misses, "hit_rate", fmt.Sprintf("%.1f%%", hitRate))
		}
	}()

	// Build options
	opts := []sociopath.Option{
		sociopath.WithLogger(logger),
		sociopath.WithHTTPCache(httpCache),
	}
	if *useBrowser {
		opts = append(opts, sociopath.WithBrowserCookies())
	}
	if len(emails) > 0 {
		opts = append(opts, sociopath.WithEmailHints(emails...))
	}

	ctx := context.Background()

	// Helper to output results
	output := func(profiles []*profile.Profile) {
		// Set confidence to 1.0 for directly-fetched profiles (not guesses)
		for _, p := range profiles {
			if !p.IsGuess && p.Confidence == 0 {
				p.Confidence = 1.0
			}
		}
		// Sort by confidence (highest first)
		sort.Slice(profiles, func(i, j int) bool {
			return profiles[i].Confidence > profiles[j].Confidence
		})
		if prettyOutput {
			printPretty(profiles)
		} else if err := outputJSON(profiles); err != nil {
			fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
			os.Exit(1)
		}
	}

	switch {
	case len(emails) > 0 && flag.NArg() == 0:
		// Email-only lookup mode
		var profiles []*sociopath.Profile
		var err error
		if *recursive || *guessMode {
			profiles, err = sociopath.FetchEmailRecursive(ctx, emails, opts...)
		} else {
			profiles, err = sociopath.FetchEmail(ctx, emails, opts...)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1) //nolint:gocritic // exitAfterDefer is acceptable in main
		}
		output(profiles)
	case *guessMode:
		// Guess mode implies recursive and accepts username or URL
		var profiles []*sociopath.Profile
		var err error

		if isURL(input) {
			profiles, err = sociopath.FetchRecursiveWithGuess(ctx, input, opts...)
		} else {
			// Treat as username and guess across platforms
			profiles, err = sociopath.GuessFromUsername(ctx, input, opts...)
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		output(profiles)
	case *recursive:
		if !isURL(input) {
			fmt.Fprint(os.Stderr, "Error: -r mode requires a URL, not a username\n")
			os.Exit(1)
		}
		profiles, err := sociopath.FetchRecursive(ctx, input, opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		output(profiles)
	default:
		if !isURL(input) {
			fmt.Fprint(os.Stderr, "Error: requires a URL, not a username. Use --guess to search by username.\n")
			os.Exit(1)
		}
		p, err := sociopath.Fetch(ctx, input, opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		output([]*profile.Profile{p})
	}
}

func isURL(s string) bool {
	// URLs, mailto:, or email addresses that match a platform
	return strings.Contains(s, "://") ||
		strings.HasPrefix(s, "http") ||
		strings.HasPrefix(strings.ToLower(s), "mailto:") ||
		sociopath.PlatformForURL(s) != "generic"
}

func outputJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// ANSI color codes for modern terminal output.
const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	cyan    = "\033[36m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
)

// printPretty outputs profiles in a compact, modern CLI format.
func printPretty(profiles []*profile.Profile) {
	for i, p := range profiles {
		if i > 0 {
			fmt.Println()
		}
		printProfile(p)
	}
}

func printProfile(prof *profile.Profile) {
	// Header: platform name with status indicators
	platformColor := blue
	if prof.IsGuess {
		platformColor = magenta
	}
	badge := fmt.Sprintf("%s%s[%s]%s", bold, platformColor, strings.ToUpper(prof.Platform), reset)

	// Status indicators
	var status []string
	if prof.AccountState != "" {
		status = append(status, fmt.Sprintf("%s⚠ %s%s", yellow, prof.AccountState, reset))
	}
	if prof.IsGuess {
		if prof.Confidence < 0.4 {
			status = append(status, fmt.Sprintf("%s%s%.0f%% LOW CONFIDENCE%s", bold, yellow, prof.Confidence*100, reset))
		} else {
			status = append(status, fmt.Sprintf("%s%.0f%%%s", dim, prof.Confidence*100, reset))
		}
	}
	if prof.Authenticated {
		status = append(status, fmt.Sprintf("%s✓auth%s", green, reset))
	}
	if prof.Error != "" {
		status = append(status, fmt.Sprintf("%s✗ %s%s", yellow, truncate(prof.Error, 40), reset))
	}

	statusStr := ""
	if len(status) > 0 {
		statusStr = " " + strings.Join(status, " ")
	}

	// Name line: DisplayName (@username) or just @username
	var nameParts []string
	if prof.DisplayName != "" {
		nameParts = append(nameParts, fmt.Sprintf("%s%s%s", bold, prof.DisplayName, reset))
	}
	if prof.Username != "" {
		nameParts = append(nameParts, fmt.Sprintf("%s@%s%s", cyan, prof.Username, reset))
	}
	nameStr := strings.Join(nameParts, " ")
	if nameStr == "" && prof.PageTitle != "" {
		nameStr = fmt.Sprintf("%s%s%s", dim, truncate(prof.PageTitle, 60), reset)
	}

	fmt.Printf("%s%s\n", badge, statusStr)
	if nameStr != "" {
		fmt.Printf("  %s\n", nameStr)
	}

	// Info line: bio, location, dates - all on minimal lines
	var info []string
	if prof.Bio != "" {
		info = append(info, truncate(stripHTML(prof.Bio), 80))
	}
	if prof.Location != "" {
		info = append(info, fmt.Sprintf("📍 %s", prof.Location))
	}
	if prof.Website != "" {
		info = append(info, fmt.Sprintf("🔗 %s", shortURL(prof.Website)))
	}
	if prof.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, prof.CreatedAt); err == nil {
			info = append(info, fmt.Sprintf("📅 %s", t.Format("2006-01-02")))
		}
	}
	if len(info) > 0 {
		fmt.Printf("  %s%s%s\n", dim, strings.Join(info, " · "), reset)
	}

	// Fields (compact key=value format)
	if len(prof.Fields) > 0 {
		var fields []string
		keys := sortedKeys(prof.Fields)
		for _, k := range keys {
			v := prof.Fields[k]
			if v != "" && k != "headline" { // headline is usually same as bio
				fields = append(fields, fmt.Sprintf("%s=%s", k, truncate(v, 30)))
			}
		}
		if len(fields) > 0 {
			fmt.Printf("  %s%s%s\n", dim, strings.Join(fields, " · "), reset)
		}
	}

	// Groups/orgs (compact)
	if len(prof.Groups) > 0 {
		groups := prof.Groups
		if len(groups) > 5 {
			groups = groups[:5]
		}
		fmt.Printf("  %s⚙ %s%s\n", dim, strings.Join(groups, ", "), reset)
	}

	// Social links (compact)
	if len(prof.SocialLinks) > 0 {
		links := make([]string, 0, len(prof.SocialLinks))
		for _, link := range prof.SocialLinks {
			links = append(links, shortURL(link))
		}
		if len(links) > 4 {
			links = links[:4]
			links = append(links, "...")
		}
		fmt.Printf("  %s→ %s%s\n", blue, strings.Join(links, " · "), reset)
	}

	// Repositories (compact)
	if len(prof.Repositories) > 0 {
		repos := make([]string, 0, len(prof.Repositories))
		for _, r := range prof.Repositories {
			name := r.Name
			if r.Language != "" {
				name = fmt.Sprintf("%s[%s]", r.Name, r.Language)
			}
			repos = append(repos, name)
		}
		if len(repos) > 4 {
			repos = repos[:4]
			repos = append(repos, "...")
		}
		fmt.Printf("  %s📦 %s%s\n", dim, strings.Join(repos, " · "), reset)
	}

	// Posts/comments (one per line)
	if len(prof.Posts) > 0 {
		maxPosts := min(5, len(prof.Posts))
		for i := range maxPosts {
			post := prof.Posts[i]
			var line string
			if post.Title != "" {
				line = truncate(stripHTML(post.Title), 70)
			} else if post.Content != "" {
				line = truncate(stripHTML(post.Content), 70)
			}
			if line != "" {
				prefix := "💬"
				switch post.Type {
				case "article", "post":
					prefix = "📝"
				case "video":
					prefix = "🎬"
				default:
					// Keep 💬 for comments and other types
				}
				fmt.Printf("  %s%s %s%s\n", dim, prefix, line, reset)
			}
		}
		if len(prof.Posts) > 5 {
			fmt.Printf("  %s   ...and %d more%s\n", dim, len(prof.Posts)-5, reset)
		}
	}

	// Content preview (truncated)
	if prof.Content != "" {
		content := stripHTML(prof.Content)
		content = collapseWhitespace(content)
		if len(content) > 400 {
			content = content[:400] + "..."
		}
		if content != "" {
			// Wrap at ~80 chars with indent
			wrapped := wrapText(content, 76)
			for _, line := range wrapped {
				fmt.Printf("  %s│%s %s\n", dim, reset, line)
			}
		}
	}

	// URL at the bottom
	fmt.Printf("  %s%s%s\n", dim, prof.URL, reset)
}

// Helper functions for pretty printing.

func truncate(s string, maxLen int) string {
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

func shortURL(u string) string {
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	u = strings.TrimPrefix(u, "www.")
	u = strings.TrimSuffix(u, "/")
	if len(u) > 50 {
		u = u[:47] + "..."
	}
	return u
}

var htmlTagRE = regexp.MustCompile(`<[^>]*>`)

func stripHTML(s string) string {
	s = htmlTagRE.ReplaceAllString(s, " ")
	s = strings.ReplaceAll(s, "&nbsp;", " ")
	s = strings.ReplaceAll(s, "&amp;", "&")
	s = strings.ReplaceAll(s, "&lt;", "<")
	s = strings.ReplaceAll(s, "&gt;", ">")
	s = strings.ReplaceAll(s, "&quot;", "\"")
	s = strings.ReplaceAll(s, "&#39;", "'")
	return strings.TrimSpace(s)
}

func collapseWhitespace(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

func wrapText(s string, width int) []string {
	var lines []string
	words := strings.Fields(s)
	var line string
	for _, w := range words {
		switch {
		case line == "":
			line = w
		case len(line)+1+len(w) <= width:
			line += " " + w
		default:
			lines = append(lines, line)
			line = w
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	// Limit to ~5 lines
	if len(lines) > 5 {
		lines = lines[:5]
		lines[4] += "..."
	}
	return lines
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
