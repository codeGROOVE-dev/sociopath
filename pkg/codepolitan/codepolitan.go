// Package codepolitan is a stub for CodePolitan support.
// CodePolitan (codepolitan.com) is an Indonesian programming learning platform.
//
// TODO: No public user profile pages found during research.
// Implement if user provides example profile URLs showing accessible profile structure.
package codepolitan

import (
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

const platform = "codepolitan"

// Match returns false because no public profile structure has been identified.
// TODO: Implement when profile URL format is confirmed.
func Match(url string) bool {
	return false
}

// AuthRequired returns false (will likely be public if/when profiles are found).
func AuthRequired() bool {
	return false
}

//nolint:deadcode,unused // Stub for future implementation
func init() {
	// Do not register until profile URL format is confirmed
	// profile.Register(platformInfo{})
}

//nolint:deadcode,unused // Stub for future implementation
type platformInfo struct{}

//nolint:deadcode,unused // Stub for future implementation
func (platformInfo) Name() string { return platform }

//nolint:deadcode,unused // Stub for future implementation
func (platformInfo) Type() profile.PlatformType { return profile.PlatformTypeOther }

//nolint:deadcode,unused // Stub for future implementation
func (platformInfo) Match(url string) bool { return Match(url) }

//nolint:deadcode,unused // Stub for future implementation
func (platformInfo) AuthRequired() bool { return AuthRequired() }
