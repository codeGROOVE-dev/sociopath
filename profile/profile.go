// Package profile defines the common types for social media profile extraction.
package profile

import (
	"context"
	"errors"
	"time"
)

// Common errors returned by platform packages.
var (
	ErrAuthRequired    = errors.New("authentication required")
	ErrNoCookies       = errors.New("no cookies available")
	ErrProfileNotFound = errors.New("profile not found")
	ErrRateLimited     = errors.New("rate limited")
)

// Profile represents extracted data from a social media profile.
//
//nolint:govet // fieldalignment: intentional layout for readability
type Profile struct {
	// Metadata
	Platform      string // Platform name: "linkedin", "twitter", "mastodon", etc.
	URL           string // Original URL fetched
	Authenticated bool   // Whether login cookies were used

	// Core profile data
	Username string // Handle/username (without @ prefix)
	Name     string // Display name
	Bio      string // Profile bio/description
	Location string // Geographic location
	Website  string // Personal website URL

	// Platform-specific fields
	Fields map[string]string // Additional platform-specific data (headline, employer, etc.)

	// For further crawling
	SocialLinks []string // Other social media URLs detected on the profile

	// Fallback for unrecognized platforms
	Unstructured string // Raw markdown content (HTML->MD conversion)

	// Guess mode fields (omitted from JSON when empty)
	IsGuess    bool     `json:",omitempty"` // True if this profile was discovered via guessing
	Confidence float64  `json:",omitempty"` // Confidence score 0.0-1.0 for guessed profiles
	GuessMatch []string `json:",omitempty"` // Reasons for match (e.g., "username", "name", "location")
}

// HTTPCache defines the interface for caching HTTP responses.
// This is compatible with locator's httpcache package.
type HTTPCache interface {
	Get(ctx context.Context, url string) (data []byte, etag string, headers map[string]string, found bool)
	SetAsync(ctx context.Context, url string, data []byte, etag string, headers map[string]string) error
	SetAsyncWithTTL(ctx context.Context, url string, data []byte, etag string, headers map[string]string, ttl time.Duration) error
}
