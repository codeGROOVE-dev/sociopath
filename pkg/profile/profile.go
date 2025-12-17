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

// AccountState indicates the current state of a user account.
type AccountState string

// Account state constants.
const (
	AccountStateActive     AccountState = ""           // Account is active (default, omitted from JSON)
	AccountStateRenamed    AccountState = "renamed"    // Account was renamed to a new username
	AccountStateDeleted    AccountState = "deleted"    // Account was deleted but historical data recovered
	AccountStateUnverified AccountState = "unverified" // Profile exists but ownership could not be verified
)

// PlatformType categorizes what kind of content a platform primarily hosts.
// This enables cross-platform matching bonuses (e.g., same username on GitHub and GitLab).
type PlatformType string

// Platform type constants for categorizing platforms by their primary content type.
const (
	PlatformTypeCode      PlatformType = "code"      // Code hosting: GitHub, GitLab, Codeberg, etc.
	PlatformTypeBlog      PlatformType = "blog"      // Long-form writing: Medium, Substack, Dev.to, etc.
	PlatformTypeMicroblog PlatformType = "microblog" // Short posts: Twitter, Mastodon, Bluesky, etc.
	PlatformTypeVideo     PlatformType = "video"     // Video content: YouTube, TikTok, Twitch, etc.
	PlatformTypeForum     PlatformType = "forum"     // Discussion forums: Reddit, HN, Lobsters, etc.
	PlatformTypeGaming    PlatformType = "gaming"    // Gaming platforms: Steam, etc.
	PlatformTypeSocial    PlatformType = "social"    // General social: LinkedIn, Instagram, VK, etc.
	PlatformTypePackage   PlatformType = "package"   // Package registries: npm, PyPI, crates.io, etc.
	PlatformTypeSecurity  PlatformType = "security"  // Security platforms: HackerOne, Bugcrowd, etc.
	PlatformTypeOther     PlatformType = "other"     // Uncategorized platforms
)

// Post represents a piece of user-generated content (post, comment, video, etc.).
type Post struct {
	Type     PostType `json:"type"`               // Type of content
	Title    string   `json:"title,omitempty"`    // Title (for videos, articles, posts)
	Content  string   `json:"content,omitempty"`  // Body text or description
	URL      string   `json:"url,omitempty"`      // Link to the original content
	Category string   `json:"category,omitempty"` // Category (subreddit, channel, topic, etc.)
	Date     string   `json:"date,omitempty"`     // Date/timestamp of the post (ISO 8601 or human-readable)
}

// Repository represents a code repository (pinned/popular on GitHub, etc.).
type Repository struct {
	Name        string `json:"name"`                  // Repository name
	Description string `json:"description,omitempty"` // Repository description
	URL         string `json:"url,omitempty"`         // Repository URL
	Language    string `json:"language,omitempty"`    // Primary programming language
	Stars       string `json:"stars,omitempty"`       // Star count (as string, e.g. "1.2k")
	Forks       string `json:"forks,omitempty"`       // Fork count
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
	Username    string   `json:",omitempty"` // Handle/username (without @ prefix)
	DisplayName string   `json:",omitempty"` // Person's chosen display name on the platform (not page title or error messages)
	PageTitle   string   `json:",omitempty"` // HTML page title (may contain errors or site name)
	AvatarURL   string   `json:",omitempty"` // Profile photo/avatar URL
	AvatarHash  uint64   `json:",omitempty"` // Perceptual hash of avatar for cross-platform matching
	Bio         string   `json:",omitempty"` // Profile bio/description
	Location    string   `json:",omitempty"` // Geographic location
	Website     string   `json:",omitempty"` // Personal website URL
	CreatedAt   string   `json:",omitempty"` // Account creation date (ISO timestamp)
	UpdatedAt   string   `json:",omitempty"` // Most recent activity or profile update (ISO timestamp)
	UTCOffset   *float64 `json:",omitempty"` // UTC offset in hours (e.g., -8 for PST, 5.5 for IST)

	// Account state (for renamed/deleted accounts)
	AccountState AccountState `json:",omitempty"` // Current account state (renamed, deleted)
	Aliases      []string     `json:",omitempty"` // Alternative usernames (old names, aliases) for cross-platform matching
	DatabaseID   string       `json:",omitempty"` // Platform-specific unique ID (survives renames)
	ArchivedAt   string       `json:",omitempty"` // Timestamp of archived snapshot used (if deleted)

	// Platform-specific fields
	Fields map[string]string `json:",omitempty"` // Additional platform-specific data (headline, employer, etc.)
	Badges map[string]string `json:",omitempty"` // Achievements/badges with counts (e.g., "Pair Extraordinaire": "4")
	Groups []string          `json:",omitempty"` // Organizations, teams, or groups the user belongs to (sorted)

	// For further crawling
	SocialLinks []string `json:",omitempty"` // Other social media URLs detected on the profile

	// User-generated content (posts, comments, videos, etc.)
	Posts []Post `json:",omitempty"` // Structured content extracted from the profile

	// Code repositories (pinned/popular repos from GitHub, etc.)
	Repositories []Repository `json:",omitempty"`

	// Unstructured content (README, page content, etc.)
	Content string `json:",omitempty"` // Raw HTML content (README, page body)

	// Guess mode fields (omitted from JSON when empty)
	IsGuess    bool     `json:",omitempty"` // True if this profile was discovered via guessing
	Confidence float64  `json:",omitempty"` // Confidence score 0.0-1.0 for guessed profiles
	GuessMatch []string `json:",omitempty"` // Reasons for match (e.g., "username", "name", "location")
}
