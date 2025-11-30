package profile

import (
	"errors"
	"testing"
)

func TestErrorTypes(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{"ErrAuthRequired", ErrAuthRequired, "authentication required"},
		{"ErrNoCookies", ErrNoCookies, "no cookies available"},
		{"ErrProfileNotFound", ErrProfileNotFound, "profile not found"},
		{"ErrRateLimited", ErrRateLimited, "rate limited"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.want {
				t.Errorf("got %q, want %q", tt.err.Error(), tt.want)
			}
		})
	}
}

func TestErrorWrapping(t *testing.T) {
	wrapped := errors.Join(ErrAuthRequired, errors.New("LinkedIn requires cookies"))

	if !errors.Is(wrapped, ErrAuthRequired) {
		t.Error("wrapped error should match ErrAuthRequired")
	}
}

func TestProfileDefaults(t *testing.T) {
	p := Profile{}

	if p.Platform != "" {
		t.Error("Platform should be empty by default")
	}
	if p.Authenticated {
		t.Error("Authenticated should be false by default")
	}
	if p.Fields != nil {
		t.Error("Fields should be nil by default")
	}
	if p.SocialLinks != nil {
		t.Error("SocialLinks should be nil by default")
	}
}
