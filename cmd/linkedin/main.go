// Command linkedin is a CLI tool for fetching LinkedIn user profile data.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"os"

	"github.com/tstromberg/linkedin"
)

var (
	verbose = flag.Bool("v", false, "verbose logging")
	debug   = flag.Bool("debug", false, "debug cookie information")
)

func main() {
	flag.Parse()

	if *verbose {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <linkedin-profile-url>\n\n", os.Args[0])
		fmt.Fprint(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
		fmt.Fprint(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s https://www.linkedin.com/in/thomas-str%%C3%%B6mberg-9977261/\n", os.Args[0])
		os.Exit(1)
	}

	ctx := context.Background()

	client, err := linkedin.New(ctx)
	if err != nil {
		log.Fatalf("Failed to create LinkedIn client: %v", err)
	}

	if *debug {
		client.EnableDebug()
	}

	profileURL := flag.Args()[0]
	profile, err := client.FetchProfile(ctx, profileURL)
	if err != nil {
		log.Fatalf("Failed to fetch profile: %v", err)
	}

	fmt.Print("\nLinkedIn Profile\n")
	fmt.Print("================\n")
	fmt.Printf("Name:     %s\n", profile.Name)
	fmt.Printf("Headline: %s\n", profile.Headline)
	fmt.Printf("Employer: %s\n", profile.CurrentEmployer)
	fmt.Printf("Location: %s\n", profile.Location)
	fmt.Printf("URL:      %s\n", profile.ProfileURL)
}
