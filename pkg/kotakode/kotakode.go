// Package kotakode is a stub for Kotakode support.
// Kotakode (kotakode.com) is an Indonesian Q&A platform for programmers.
//
// TODO: Site is currently returning 503 errors (as of Dec 2024).
// Implement when site becomes accessible again.
// Expected URL pattern: kotakode.com/users/{username}
package kotakode

import (
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "kotakode"

// Match returns false because implementation is not ready.
// TODO: Implement when site is accessible.
func Match(url string) bool {
	return false
}

// AuthRequired returns false (will be public when implemented).
func AuthRequired() bool {
	return false
}

//nolint:deadcode,unused // Stub for future implementation
func init() {
	// Do not register until implementation is ready
	// profile.Register(platformInfo{})
}

//nolint:deadcode,unused // Stub for future implementation
type platformInfo struct{}

//nolint:deadcode,unused // Stub for future implementation
func (platformInfo) Name() string { return platform }

//nolint:deadcode,unused // Stub for future implementation
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeForum }

//nolint:deadcode,unused // Stub for future implementation
func (platformInfo) Match(url string) bool { return Match(url) }

//nolint:deadcode,unused // Stub for future implementation
func (platformInfo) AuthRequired() bool { return AuthRequired() }
