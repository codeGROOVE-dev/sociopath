// Package google fetches Google/Gmail user profile data via OSINT methods.
//
// This package supports:
//   - Gmail addresses: e.g., "user@gmail.com" or "mailto:user@gmail.com"
//   - GAIA IDs: e.g., "118127988220485054809" or Google Maps contrib URLs
//   - Google Maps contrib URLs: google.com/maps/contrib/{GAIA_ID}
//   - Album archive URLs: get.google.com/albumarchive/{GAIA_ID}
//
// For Gmail addresses without a GAIA ID, the profile stores the email for
// future lookups. When a GAIA ID is available, it fetches public Maps data.
package google

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "google"

var (
	// gaiaIDRegex matches a 21-digit GAIA ID.
	gaiaIDRegex = regexp.MustCompile(`^\d{21}$`)

	// gmailRegex matches Gmail addresses with optional mailto: prefix.
	gmailRegex = regexp.MustCompile(`(?i)^(?:mailto:)?([a-zA-Z0-9._%+-]+@gmail\.com)$`)

	// mapsContribRegex extracts GAIA ID from Google Maps contributor URLs.
	mapsContribRegex = regexp.MustCompile(`(?i)google\.com/maps/contrib/(\d{21})`)

	// albumArchiveRegex extracts GAIA ID from Google Photos album archive URLs.
	albumArchiveRegex = regexp.MustCompile(`(?i)get\.google\.com/albumarchive/(\d{21})`)
)

// Match returns true if the input is a Gmail address, GAIA ID, or Google Maps contrib URL.
func Match(input string) bool {
	input = strings.TrimSpace(input)
	return gaiaIDRegex.MatchString(input) ||
		gmailRegex.MatchString(input) ||
		mapsContribRegex.MatchString(input) ||
		albumArchiveRegex.MatchString(input)
}

// AuthRequired returns false because Maps lookups are public.
func AuthRequired() bool { return false }

// Client handles Google OSINT requests.
type Client struct {
	httpClient *http.Client
	cache      httpcache.Cacher
	logger     *slog.Logger
}

// Option configures a Client.
type Option func(*config)

type config struct {
	cache  httpcache.Cacher
	logger *slog.Logger
}

// WithHTTPCache sets the HTTP cache.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// New creates a Google OSINT client.
func New(_ context.Context, opts ...Option) (*Client, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	return &Client{
		httpClient: &http.Client{Timeout: 10 * time.Second},
		cache:      cfg.cache,
		logger:     cfg.logger,
	}, nil
}

// Fetch retrieves Google profile data from a Gmail address or GAIA ID.
func (c *Client) Fetch(ctx context.Context, input string) (*profile.Profile, error) {
	input = strings.TrimSpace(input)

	var gaiaID string
	var email string

	// Parse the input to extract GAIA ID or email
	switch {
	case gaiaIDRegex.MatchString(input):
		gaiaID = input
	case gmailRegex.MatchString(input):
		matches := gmailRegex.FindStringSubmatch(input)
		if len(matches) > 1 {
			email = strings.ToLower(matches[1])
		}
	case mapsContribRegex.MatchString(input):
		matches := mapsContribRegex.FindStringSubmatch(input)
		if len(matches) > 1 {
			gaiaID = matches[1]
		}
	case albumArchiveRegex.MatchString(input):
		matches := albumArchiveRegex.FindStringSubmatch(input)
		if len(matches) > 1 {
			gaiaID = matches[1]
		}
	default:
		return nil, fmt.Errorf("could not parse input: %s", input)
	}

	c.logger.InfoContext(ctx, "fetching google profile", "gaia_id", gaiaID, "email", email)

	prof := &profile.Profile{
		Platform: platform,
		Fields:   make(map[string]string),
	}

	// Handle Gmail address (store for future use)
	if email != "" {
		prof.Username = strings.TrimSuffix(email, "@gmail.com")
		prof.Fields["email"] = email
		prof.URL = "mailto:" + email
		// Without GAIA ID, we can only store the email for future lookups
		return prof, nil
	}

	// Handle GAIA ID - fetch Maps data
	if gaiaID != "" {
		prof.Fields["gaia_id"] = gaiaID
		prof.URL = fmt.Sprintf("https://www.google.com/maps/contrib/%s", gaiaID)

		mapsData, err := c.fetchMapsData(ctx, gaiaID)
		if err != nil {
			c.logger.WarnContext(ctx, "failed to fetch maps data", "gaia_id", gaiaID, "error", err)
			prof.Error = fmt.Sprintf("maps fetch failed: %v", err)
		} else {
			prof.Name = mapsData.name
			prof.Posts = append(prof.Posts, mapsData.reviews...)
			prof.Posts = append(prof.Posts, mapsData.photos...)

			for k, v := range mapsData.stats {
				prof.Fields[k] = strconv.Itoa(v)
			}

			if loc := inferLocation(mapsData.reviews); loc != "" {
				prof.Location = loc
			}
		}

		prof.SocialLinks = append(prof.SocialLinks,
			fmt.Sprintf("https://get.google.com/albumarchive/%s", gaiaID))
	}

	return prof, nil
}

// mapsResult holds parsed Maps data.
type mapsResult struct {
	name    string
	stats   map[string]int
	reviews []profile.Post
	photos  []profile.Post
}

// fetchMapsData retrieves reviews and photos from Google Maps for a GAIA ID.
func (c *Client) fetchMapsData(ctx context.Context, gaiaID string) (*mapsResult, error) {
	result := &mapsResult{stats: make(map[string]int)}

	statsURL := fmt.Sprintf(
		"https://www.google.com/locationhistory/preview/mas?authuser=0&hl=en&gl=us&pb=%s",
		buildStatsPB(gaiaID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, statsURL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("creating stats request: %w", err)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0")

	body, err := c.doRequest(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("fetching stats: %w", err)
	}

	result.stats, result.name = parseStatsResponse(body, c.logger)

	totalItems := result.stats["Reviews"] + result.stats["Ratings"] + result.stats["Photos"]
	if totalItems == 0 {
		return result, nil
	}

	if reviews, err := c.fetchReviews(ctx, gaiaID); err != nil {
		c.logger.WarnContext(ctx, "failed to fetch reviews", "error", err)
	} else {
		result.reviews = reviews
	}

	if photos, err := c.fetchPhotos(ctx, gaiaID); err != nil {
		c.logger.WarnContext(ctx, "failed to fetch photos", "error", err)
	} else {
		result.photos = photos
	}

	return result, nil
}

func (c *Client) fetchReviews(ctx context.Context, gaiaID string) ([]profile.Post, error) {
	reviewsURL := fmt.Sprintf(
		"https://www.google.com/locationhistory/preview/mas?authuser=0&hl=en&gl=us&pb=%s",
		buildReviewsPB(gaiaID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reviewsURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0")

	body, err := c.doRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	return parseReviewsResponse(body)
}

func (c *Client) fetchPhotos(ctx context.Context, gaiaID string) ([]profile.Post, error) {
	photosURL := fmt.Sprintf(
		"https://www.google.com/locationhistory/preview/mas?authuser=0&hl=en&gl=us&pb=%s",
		buildPhotosPB(gaiaID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, photosURL, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; rv:128.0) Gecko/20100101 Firefox/128.0")

	body, err := c.doRequest(ctx, req)
	if err != nil {
		return nil, err
	}

	return parsePhotosResponse(body)
}

func (c *Client) doRequest(ctx context.Context, req *http.Request) ([]byte, error) {
	if c.cache != nil {
		return httpcache.FetchURL(ctx, c.cache, c.httpClient, req, c.logger)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best effort close

	if resp.StatusCode == http.StatusFound {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "google.com/sorry") {
			return nil, errors.New("rate limited by Google")
		}
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// Protobuf parameter builders - these are opaque strings based on GHunt's analysis.
var (
	statsPBTemplate = "!1s%s!2m3!1sYE3rYc2rEsqOlwSHx534DA!7e81!15i14416" +
		"!6m2!4b1!7b1!9m0!16m4!1i100!4b1!5b1!6BQ0FFU0JrVm5TVWxEenc9PQ"

	reviewsPBTemplate = "!1s%s!2m5!1soViSYcvVG6iJytMPk6amiA8%%3A1" +
		"!2zMWk6NCx0OjE0MzIzLGU6MCxwOm9WaVNZY3ZWRzZpSnl0TVBrNmFtaUE4OjE" +
		"!4m1!2i14323!7e81!6m2!4b1!7b1!9m0!10m6!1b1!2b1!5b1!8b1!9m1!1e3" +
		"!14m69!1m57!1m4!1m3!1e3!1e2!1e4!3m5!2m4!3m3!1m2!1i260!2i365!4m1!3i10" +
		"!10b1!11m42!1m3!1e1!2b0!3e3!1m3!1e2!2b1!3e2!1m3!1e2!2b0!3e3" +
		"!1m3!1e8!2b0!3e3!1m3!1e10!2b0!3e3!1m3!1e10!2b1!3e2!1m3!1e9!2b1!3e2" +
		"!1m3!1e10!2b0!3e3!1m3!1e10!2b1!3e2!1m3!1e10!2b0!3e4!2b1!4b1" +
		"!2m5!1e1!1e4!1e3!1e5!1e2!3b0!4b1!5m1!1e1!7b1!16m3!1i10!4b1!5b1"

	photosPBTemplate = "!1s%s!2m3!1spQUAYoPQLcOTlwT9u6-gDA!7e81!15i18404!9m0" +
		"!14m69!1m57!1m4!1m3!1e3!1e2!1e4!3m5!2m4!3m3!1m2!1i260!2i365!4m1!3i10" +
		"!10b1!11m42!1m3!1e1!2b0!3e3!1m3!1e2!2b1!3e2!1m3!1e2!2b0!3e3" +
		"!1m3!1e8!2b0!3e3!1m3!1e10!2b0!3e3!1m3!1e10!2b1!3e2!1m3!1e9!2b1!3e2" +
		"!1m3!1e10!2b0!3e3!1m3!1e10!2b1!3e2!1m3!1e10!2b0!3e4!2b1!4b1" +
		"!2m5!1e1!1e4!1e3!1e5!1e2!3b1!4b1!5m1!1e1!7b1"
)

func buildStatsPB(gaiaID string) string   { return fmt.Sprintf(statsPBTemplate, gaiaID) }
func buildReviewsPB(gaiaID string) string { return fmt.Sprintf(reviewsPBTemplate, gaiaID) }
func buildPhotosPB(gaiaID string) string  { return fmt.Sprintf(photosPBTemplate, gaiaID) }

// parseStatsResponse parses the Maps stats response.
func parseStatsResponse(data []byte, logger *slog.Logger) (stats map[string]int, name string) {
	stats = make(map[string]int)

	content := stripJSONPrefix(data)
	var rawData []any
	if err := json.Unmarshal([]byte(content), &rawData); err != nil {
		logger.Debug("failed to parse stats response", "error", err)
		return stats, name
	}

	// Extract name from [16][5][0][0]
	name = extractString(rawData, 16, 5, 0, 0)

	// Extract stats from [16][8][0] - each section has label at [6] and count at [7]
	if sections := extractArray(rawData, 16, 8, 0); sections != nil {
		for _, sec := range sections {
			if secArr, ok := sec.([]any); ok && len(secArr) > 7 {
				label, lok := secArr[6].(string)
				count, cok := secArr[7].(float64)
				if lok && cok && label != "" {
					stats[label] = int(count)
				}
			}
		}
	}

	return stats, name
}

func parseReviewsResponse(data []byte) ([]profile.Post, error) {
	content := stripJSONPrefix(data)
	var rawData []any
	if err := json.Unmarshal([]byte(content), &rawData); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	var posts []profile.Post
	// Reviews at [24][0]
	if reviews := extractArray(rawData, 24, 0); reviews != nil {
		for _, review := range reviews {
			if post := parseReview(review); post != nil {
				posts = append(posts, *post)
			}
		}
	}

	return posts, nil
}

func parsePhotosResponse(data []byte) ([]profile.Post, error) {
	content := stripJSONPrefix(data)
	var rawData []any
	if err := json.Unmarshal([]byte(content), &rawData); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	var posts []profile.Post
	// Photos at [22][1]
	if photos := extractArray(rawData, 22, 1); photos != nil {
		for _, photo := range photos {
			if post := parsePhoto(photo); post != nil {
				posts = append(posts, *post)
			}
		}
	}

	return posts, nil
}

func parseReview(review any) *profile.Post {
	arr, ok := review.([]any)
	if !ok || len(arr) < 2 {
		return nil
	}

	post := &profile.Post{Type: profile.PostTypeComment}

	// Location at arr[1]: name at [2], address at [3]
	if locArr, ok := arr[1].([]any); ok && len(locArr) > 3 {
		if cat, ok := locArr[2].(string); ok {
			post.Category = cat
		}
		if title, ok := locArr[3].(string); ok {
			post.Title = title
		}
	}

	// Review content at arr[6][2][15][0][0]
	post.Content = extractString(arr, 6, 2, 15, 0, 0)

	if post.Category == "" && post.Content == "" {
		return nil
	}
	return post
}

func parsePhoto(photo any) *profile.Post {
	arr, ok := photo.([]any)
	if !ok || len(arr) < 1 {
		return nil
	}

	post := &profile.Post{Type: profile.PostTypePost}

	// Photo URL at arr[0][6][0]
	if urlStr := extractString(arr, 0, 6, 0); urlStr != "" {
		if idx := strings.Index(urlStr, "="); idx > 0 {
			urlStr = urlStr[:idx]
		}
		post.URL = urlStr
	}

	// Location at arr[1]: name at [2], address at [3]
	if len(arr) > 1 {
		if locArr, ok := arr[1].([]any); ok && len(locArr) > 3 {
			if cat, ok := locArr[2].(string); ok {
				post.Category = cat
			}
			if title, ok := locArr[3].(string); ok {
				post.Title = title
			}
		}
	}

	if post.URL == "" && post.Category == "" {
		return nil
	}
	return post
}

// Helper functions for navigating nested JSON arrays.

func stripJSONPrefix(data []byte) string {
	content := string(data)
	if idx := strings.Index(content, "\n"); idx >= 0 {
		content = content[idx+1:]
	}
	return content
}

func extractArray(data any, indices ...int) []any {
	current := data
	for _, idx := range indices {
		arr, ok := current.([]any)
		if !ok || idx >= len(arr) {
			return nil
		}
		current = arr[idx]
	}
	if result, ok := current.([]any); ok {
		return result
	}
	return nil
}

func extractString(data any, indices ...int) string {
	current := data
	for _, idx := range indices {
		arr, ok := current.([]any)
		if !ok || idx >= len(arr) {
			return ""
		}
		current = arr[idx]
	}
	if s, ok := current.(string); ok {
		return s
	}
	return ""
}

func inferLocation(reviews []profile.Post) string {
	if len(reviews) == 0 {
		return ""
	}

	locations := make(map[string]int)
	for _, r := range reviews {
		if r.Title == "" {
			continue
		}
		parts := strings.Split(r.Title, ",")
		if len(parts) >= 2 {
			loc := strings.TrimSpace(parts[len(parts)-2]) + ", " +
				strings.TrimSpace(parts[len(parts)-1])
			locations[loc]++
		}
	}

	var maxLoc string
	var maxCount int
	for loc, count := range locations {
		if count > maxCount {
			maxCount = count
			maxLoc = loc
		}
	}
	return maxLoc
}
