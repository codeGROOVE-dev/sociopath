package auth

import (
	"context"
	"os"
)

// platformEnvVars maps platform names to their environment variable configurations.
// Each entry maps env var name to cookie name.
var platformEnvVars = map[string]map[string]string{
	"linkedin": {
		"LINKEDIN_LI_AT":      "li_at",
		"LINKEDIN_JSESSIONID": "JSESSIONID",
		"LINKEDIN_LIDC":       "lidc",
		"LINKEDIN_BCOOKIE":    "bcookie",
	},
	"twitter": {
		"TWITTER_AUTH_TOKEN": "auth_token",
		"TWITTER_CT0":        "ct0",
		"TWITTER_TWID":       "twid",
		"TWITTER_GUEST_ID":   "guest_id",
		"TWITTER_KDT":        "kdt",
		"TWITTER_ATT":        "att",
	},
	"instagram": {
		"INSTAGRAM_SESSIONID": "sessionid",
		"INSTAGRAM_CSRFTOKEN": "csrftoken",
	},
	"tiktok": {
		"TIKTOK_SESSIONID": "sessionid",
	},
	"vkontakte": {
		"VK_REMIXSID": "remixsid",
	},
}

// EnvSource reads cookies from environment variables.
type EnvSource struct{}

// Cookies returns cookies for the given platform from environment variables.
func (EnvSource) Cookies(_ context.Context, platform string) (map[string]string, error) {
	envMap, ok := platformEnvVars[platform]
	if !ok {
		return nil, nil //nolint:nilnil // no cookies for unknown platform is not an error
	}

	cookies := make(map[string]string)
	for envVar, cookieName := range envMap {
		if value := os.Getenv(envVar); value != "" {
			cookies[cookieName] = value
		}
	}

	if len(cookies) == 0 {
		return nil, nil //nolint:nilnil // no env vars set is not an error
	}
	return cookies, nil
}

// EnvVarsForPlatform returns the environment variable names for a platform.
// This is useful for generating help messages.
func EnvVarsForPlatform(platform string) []string {
	envMap, ok := platformEnvVars[platform]
	if !ok {
		return nil
	}

	vars := make([]string, 0, len(envMap))
	for envVar := range envMap {
		vars = append(vars, envVar)
	}
	return vars
}
