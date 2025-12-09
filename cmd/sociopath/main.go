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

func main() {
	debug := flag.Bool("debug", false, "enable debug logging")
	verbose := flag.Bool("v", false, "verbose logging (same as -debug)")
	noBrowser := flag.Bool("no-browser", false, "disable reading cookies from browser stores (enabled by default)")
	noCache := flag.Bool("no-cache", false, "disable HTTP caching (enabled by default with 75-day TTL)")
	cacheTTL := flag.Duration("cache-ttl", 75*24*time.Hour, "cache time-to-live (default: 75 days, use 24h for testing)")
	recursive := flag.Bool("r", false, "recursively fetch social media profiles from discovered links")
	guessMode := flag.Bool("guess", false, "guess related profiles based on discovered usernames (implies -r)")
	flag.Parse()

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "Usage: sociopath [options] <url>")
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
		fmt.Fprintln(os.Stderr, "  - Generic websites (no auth)")
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
	if !*noCache {
		var err error
		httpCache, err = httpcache.New(*cacheTTL)
		if err != nil {
			logger.Warn("failed to initialize cache, continuing without cache", "error", err)
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
	var opts []sociopath.Option
	opts = append(opts, sociopath.WithLogger(logger))
	if !*noBrowser {
		opts = append(opts, sociopath.WithBrowserCookies())
	}
	if httpCache != nil {
		opts = append(opts, sociopath.WithHTTPCache(httpCache))
	}

	ctx := context.Background()

	switch {
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
			os.Exit(1) //nolint:gocritic // exitAfterDefer is acceptable in main
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
	return strings.Contains(s, "://") || strings.HasPrefix(s, "http")
}

func outputJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
