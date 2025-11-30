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

	"github.com/codeGROOVE-dev/sociopath"
)

func main() {
	debug := flag.Bool("debug", false, "enable debug logging")
	verbose := flag.Bool("v", false, "verbose logging (same as -debug)")
	noBrowser := flag.Bool("no-browser", false, "disable reading cookies from browser stores (enabled by default)")
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

	url := flag.Arg(0)

	// Setup logger
	logLevel := slog.LevelInfo
	if *debug || *verbose {
		logLevel = slog.LevelDebug
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// Build options
	var opts []sociopath.Option
	opts = append(opts, sociopath.WithLogger(logger))
	if !*noBrowser {
		opts = append(opts, sociopath.WithBrowserCookies())
	}

	ctx := context.Background()

	switch {
	case *guessMode:
		// Guess mode implies recursive
		profiles, err := sociopath.FetchRecursiveWithGuess(ctx, url, opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := outputJSON(profiles); err != nil {
			fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
			os.Exit(1)
		}
	case *recursive:
		profiles, err := sociopath.FetchRecursive(ctx, url, opts...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		if err := outputJSON(profiles); err != nil {
			fmt.Fprintf(os.Stderr, "Output error: %v\n", err)
			os.Exit(1)
		}
	default:
		profile, err := sociopath.Fetch(ctx, url, opts...)
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

func outputJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
