// Package avatar provides perceptual hashing for profile avatars.
package avatar

import (
	"bytes"
	"context"
	"encoding/binary"
	"image"
	_ "image/gif"  // GIF support
	_ "image/jpeg" // JPEG support
	_ "image/png"  // PNG support
	"log/slog"
	"math/bits"
	"net/http"
	"strings"
	"time"

	"github.com/corona10/goimagehash"

	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
)

// Hash fetches an avatar image and computes its perceptual hash.
// Returns 0 on any error (network, decode, unsupported format).
// Uses the provided cache for both HTTP responses and computed hashes.
func Hash(ctx context.Context, cache httpcache.Cacher, avatarURL string, logger *slog.Logger) uint64 {
	if avatarURL == "" || isDefaultAvatar(avatarURL) {
		return 0
	}

	// Check hash cache first
	hashKey := "avhash:" + httpcache.URLToKey(avatarURL)
	if cache != nil {
		if data, err := cache.GetSet(ctx, hashKey, func(ctx context.Context) ([]byte, error) {
			h := computeHash(ctx, cache, avatarURL, logger)
			buf := make([]byte, 8)
			binary.LittleEndian.PutUint64(buf, h)
			return buf, nil
		}, cache.TTL()); err == nil && len(data) == 8 {
			return binary.LittleEndian.Uint64(data)
		}
	}

	return computeHash(ctx, cache, avatarURL, logger)
}

func computeHash(ctx context.Context, cache httpcache.Cacher, avatarURL string, logger *slog.Logger) uint64 {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, avatarURL, http.NoBody)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", httpcache.UserAgent)
	req.Header.Set("Accept", "image/webp,image/png,image/jpeg,image/gif,*/*")

	body, err := httpcache.FetchURL(ctx, cache, http.DefaultClient, req, logger)
	if err != nil {
		if logger != nil {
			logger.Debug("avatar fetch failed", "url", avatarURL, "error", err)
		}
		return 0
	}

	img, _, err := image.Decode(bytes.NewReader(body))
	if err != nil {
		if logger != nil {
			logger.Debug("avatar decode failed", "url", avatarURL, "error", err)
		}
		return 0
	}

	// Use difference hash - fast and effective for avatar comparison
	hash, err := goimagehash.DifferenceHash(img)
	if err != nil {
		if logger != nil {
			logger.Debug("avatar hash failed", "url", avatarURL, "error", err)
		}
		return 0
	}

	return hash.GetHash()
}

// Similar returns true if two avatar hashes are perceptually similar.
// A hamming distance of 10 or less (out of 64 bits) indicates similarity.
func Similar(a, b uint64) bool {
	if a == 0 || b == 0 {
		return false
	}
	return Distance(a, b) <= 10
}

// Distance returns the hamming distance between two hashes.
func Distance(a, b uint64) int {
	return bits.OnesCount64(a ^ b)
}

// Score returns a similarity score (0.0-1.0) based on hamming distance.
// Returns 0 if either hash is 0 or distance exceeds threshold.
func Score(a, b uint64) float64 {
	if a == 0 || b == 0 {
		return 0
	}
	dist := Distance(a, b)
	if dist > 10 {
		return 0
	}
	// Linear scale: 0 distance = 1.0, 10 distance = 0.0
	return 1.0 - float64(dist)/10.0
}

// isDefaultAvatar returns true for URLs that are likely default/generated avatars.
// Note: Gravatar's d= parameter (e.g., d=identicon) is just a FALLBACK option -
// if the user has a real avatar, Gravatar returns it regardless of the d= param.
// We only filter URLs where the path itself indicates a default/placeholder image.
func isDefaultAvatar(url string) bool {
	lower := strings.ToLower(url)

	// Only filter if "default" or "identicon" appears in the path, not query params
	// Split on ? to separate path from query string
	path := lower
	if idx := strings.Index(lower, "?"); idx != -1 {
		path = lower[:idx]
	}

	return strings.Contains(path, "identicon") ||
		strings.Contains(path, "default") ||
		strings.Contains(path, "avatar_default") ||
		strings.Contains(path, "placeholder")
}
