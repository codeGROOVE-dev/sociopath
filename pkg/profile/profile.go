// Package profile defines the common types for social media profile extraction.
package profile

import (
	"errors"
)

// Common errors returned by platform packages.
var (
	ErrAuthRequired    = errors.New("authentication required")
	ErrNoCookies       = errors.New("no cookies available")
	ErrProfileNotFound = errors.New("profile not found")
	ErrRateLimited     = errors.New("rate limited")
)

// PostType indicates the type of user-generated content.
type PostType string

// Post type constants for categorizing user-generated content.
const (
	PostTypeComment    PostType = "comment"
	PostTypePost       PostType = "post"
	PostTypeVideo      PostType = "video"
	PostTypeArticle    PostType = "article"
	PostTypeQuestion   PostType = "question"
	PostTypeAnswer     PostType = "answer"
	PostTypeRepository PostType = "repository"
)

// Post represents a piece of user-generated content (post, comment, video, etc.).
type Post struct {
	Type     PostType `json:"type"`               // Type of content
	Title    string   `json:"title,omitempty"`    // Title (for videos, articles, posts)
	Content  string   `json:"content,omitempty"`  // Body text or description
	URL      string   `json:"url,omitempty"`      // Link to the original content
	Category string   `json:"category,omitempty"` // Category (subreddit, channel, topic, etc.)
}

// Profile represents extracted data from a social media profile.
//
//nolint:govet // fieldalignment: intentional layout for readability
type Profile struct {
	// Metadata
	Platform      string `json:",omitempty"` // Platform name: "linkedin", "twitter", "mastodon", etc.
	URL           string `json:",omitempty"` // Original URL fetched
	Authenticated bool   `json:",omitempty"` // Whether login cookies were used
	Error         string `json:",omitempty"` // Error message if fetch failed (e.g., "login required")

	// Core profile data
	Username string `json:",omitempty"` // Handle/username (without @ prefix)
	Name     string `json:",omitempty"` // Display name
	Bio      string `json:",omitempty"` // Profile bio/description
	Location string `json:",omitempty"` // Geographic location
	Website  string `json:",omitempty"` // Personal website URL

	// Platform-specific fields
	Fields map[string]string `json:",omitempty"` // Additional platform-specific data (headline, employer, etc.)

	// Activity timestamp
	LastActive string `json:",omitempty"` // ISO timestamp of last known activity (post, comment, etc.)

	// For further crawling
	SocialLinks []string `json:",omitempty"` // Other social media URLs detected on the profile

	// User-generated content (posts, comments, videos, etc.)
	Posts []Post `json:",omitempty"` // Structured content extracted from the profile

	// Fallback for unrecognized platforms
	Unstructured string `json:",omitempty"` // Raw markdown content (HTML->MD conversion)

	// Guess mode fields (omitted from JSON when empty)
	IsGuess    bool     `json:",omitempty"` // True if this profile was discovered via guessing
	Confidence float64  `json:",omitempty"` // Confidence score 0.0-1.0 for guessed profiles
	GuessMatch []string `json:",omitempty"` // Reasons for match (e.g., "username", "name", "location")
}
