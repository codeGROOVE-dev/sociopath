// Command test-cookies tests different LinkedIn cookie combinations.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/browserutils/kooky"
	_ "github.com/browserutils/kooky/browser/all" // Import all browser cookie stores
	"github.com/tstromberg/linkedin"
)

var profileURL = flag.String("url", "", "LinkedIn profile URL to test")

type cookieCombo struct {
	name    string
	cookies []string
}

func main() {
	flag.Parse()

	if *profileURL == "" {
		fmt.Fprintf(os.Stderr, "Usage: %s -url <profile-url>\n", os.Args[0])
		os.Exit(1)
	}

	ctx := context.Background()

	// First, get all cookies from browser
	allCookies, err := kooky.ReadCookies(ctx, kooky.Valid, kooky.DomainHasSuffix("linkedin.com"))
	if err != nil {
		log.Fatalf("Failed to read cookies: %v", err)
	}

	// Build a map of cookie values
	cookieMap := make(map[string]string)
	for _, c := range allCookies {
		cookieMap[c.Name] = c.Value
	}

	fmt.Printf("Found %d LinkedIn cookies in browser\n", len(allCookies))
	fmt.Print("Testing different cookie combinations...\n\n")

	// Test combinations from most essential to all 4
	combinations := []cookieCombo{
		{"li_at only", []string{"li_at"}},
		{"li_at + JSESSIONID", []string{"li_at", "JSESSIONID"}},
		{"li_at + JSESSIONID + lidc", []string{"li_at", "JSESSIONID", "lidc"}},
		{"li_at + JSESSIONID + lidc + bcookie", []string{"li_at", "JSESSIONID", "lidc", "bcookie"}},
		{"li_at + lidc", []string{"li_at", "lidc"}},
		{"JSESSIONID + lidc", []string{"JSESSIONID", "lidc"}},
		{"li_at + bcookie", []string{"li_at", "bcookie"}},
	}

	results := make(map[string]bool)

	for _, combo := range combinations {
		success := testCombination(ctx, combo, cookieMap, *profileURL)
		results[combo.name] = success

		if success {
			fmt.Printf("✅ %s: SUCCESS\n", combo.name)
		} else {
			fmt.Printf("❌ %s: FAILED\n", combo.name)
		}
	}

	fmt.Print("\n=== Summary ===\n")
	fmt.Print("Minimum required cookies:\n")

	// Determine minimum required set
	switch {
	case results["li_at only"]:
		fmt.Print("  - li_at (sufficient alone)\n")
	case results["li_at + JSESSIONID"]:
		fmt.Print("  - li_at\n  - JSESSIONID\n")
	case results["li_at + JSESSIONID + lidc"]:
		fmt.Print("  - li_at\n  - JSESSIONID\n  - lidc\n")
	case results["li_at + JSESSIONID + lidc + bcookie"]:
		fmt.Print("  - li_at\n  - JSESSIONID\n  - lidc\n  - bcookie\n")
	default:
		fmt.Print("  - Unable to determine (all combinations failed)\n")
	}
}

func testCombination(ctx context.Context, combo cookieCombo, allCookies map[string]string, url string) bool {
	// Build cookie map for this combination
	cookies := make(map[string]string)
	for _, name := range combo.cookies {
		value, ok := allCookies[name]
		if !ok {
			fmt.Printf("⚠️  %s: Missing cookie '%s'\n", combo.name, name)
			return false
		}
		cookies[name] = value
	}

	// Create client with this combination
	client, err := linkedin.NewWithCookies(ctx, cookies)
	if err != nil {
		return false
	}

	// Try to fetch profile
	_, err = client.FetchProfile(ctx, url)
	return err == nil
}
