package auth

import "context"

// StaticSource provides cookies from a static map.
// This is useful for testing or when cookies are provided via options.
type StaticSource struct {
	cookies map[string]string
}

// NewStaticSource creates a cookie source from a static map.
func NewStaticSource(cookies map[string]string) *StaticSource {
	return &StaticSource{cookies: cookies}
}

// Cookies returns the static cookies regardless of platform.
func (s *StaticSource) Cookies(_ context.Context, _ string) (map[string]string, error) {
	if len(s.cookies) == 0 {
		return nil, nil //nolint:nilnil // empty static source is not an error
	}
	// Return a copy to prevent mutation
	result := make(map[string]string, len(s.cookies))
	for k, v := range s.cookies {
		result[k] = v
	}
	return result, nil
}
