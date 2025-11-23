// Package main demonstrates basic usage of the linkedin library.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/tstromberg/linkedin"
)

func main() {
	flag.Parse()

	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "Usage: %s <linkedin-profile-url>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Example: %s https://www.linkedin.com/in/thomas-str%%C3%%B6mberg-9977261/\n", os.Args[0])
		os.Exit(1)
	}

	ctx := context.Background()

	client, err := linkedin.New(ctx)
	if err != nil {
		log.Fatalf("Failed to create LinkedIn client: %v", err)
	}

	profileURL := flag.Args()[0]
	profile, err := client.FetchProfile(ctx, profileURL)
	if err != nil {
		log.Fatalf("Failed to fetch profile: %v", err)
	}

	fmt.Printf("Name:     %s\n", profile.Name)
	fmt.Printf("Headline: %s\n", profile.Headline)
	fmt.Printf("Employer: %s\n", profile.CurrentEmployer)
	fmt.Printf("Location: %s\n", profile.Location)
	fmt.Printf("URL:      %s\n", profile.ProfileURL)
}
