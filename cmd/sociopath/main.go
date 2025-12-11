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
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
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
	noBrowser := flag.Bool("no-browser", false, "disable reading cookies from browser stores (enabled by default)")
	noCache := flag.Bool("no-cache", false, "disable HTTP caching (enabled by default with 75-day TTL)")
	cacheTTL := flag.Duration("cache-ttl", 75*24*time.Hour, "cache time-to-live (default: 75 days, use 24h for testing)")
	recursive := flag.Bool("r", false, "recursively fetch social media profiles from discovered links")
	guessMode := flag.Bool("guess", false, "guess related profiles based on discovered usernames (implies -r)")
	var emails emailList
	flag.Var(&emails, "email", "email address to associate with profile (can be specified multiple times)")
	flag.Parse()

	// Allow --email without URL for email-only lookups
	if flag.NArg() < 1 && len(emails) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: sociopath [options] <url>")
		fmt.Fprintln(os.Stderr, "       sociopath --email <address> [--email <address2>...]")
		fmt.Fprintln(os.Stderr, "\nOptions:")
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nSupported platforms:")
		fmt.Fprintln(os.Stderr, "  - LinkedIn (reads browser cookies by default)")
		fmt.Fprintln(os.Stderr, "  - Twitter/X (reads browser cookies by default)")
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

	// Build options
	opts := []sociopath.Option{
		sociopath.WithLogger(logger),
		sociopath.WithHTTPCache(httpCache),
	}
	if !*noBrowser {
		opts = append(opts, sociopath.WithBrowserCookies())
	}
	if len(emails) > 0 {
		opts = append(opts, sociopath.WithEmailHints(emails...))
	}

	ctx := context.Background()

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
		if err := outputJSON(profiles); err != nil {
			fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
			os.Exit(1)
		}
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
		if err := outputJSON(profiles); err != nil {
			fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
			os.Exit(1)
		}
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
		if err := outputJSON(profiles); err != nil {
			fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
			os.Exit(1)
		}
	default:
		if !isURL(input) {
			fmt.Fprint(os.Stderr, "Error: requires a URL, not a username. Use --guess to search by username.\n")
			os.Exit(1)
		}
		profile, err := sociopath.Fetch(ctx, input, opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := outputJSON(profile); err != nil {
			fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
			os.Exit(1)
		}
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
