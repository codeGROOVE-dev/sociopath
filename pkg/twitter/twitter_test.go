package twitter

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://twitter.com/johndoe", true},
		{"https://x.com/johndoe", true},
		{"https://www.twitter.com/johndoe", true},
		{"https://www.x.com/johndoe", true},
		{"twitter.com/johndoe", true},
		{"x.com/johndoe", true},
		{"https://TWITTER.COM/johndoe", true},
		{"https://linkedin.com/in/johndoe", false},
		{"https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := Match(tt.url)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if !AuthRequired() {
		t.Error("Twitter should require auth")
	}
}

func TestExtractUsername(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"https://twitter.com/johndoe", "johndoe"},
		{"https://x.com/johndoe", "johndoe"},
		{"https://twitter.com/johndoe/status/123", "johndoe"},
		{"johndoe", "johndoe"},
		{"@johndoe", "johndoe"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractUsername(tt.input)
			if got != tt.want {
				t.Errorf("extractUsername(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractInitialState(t *testing.T) {
	html := `<script>window.__INITIAL_STATE__={"entities":{"users":{}}};</script>`

	got := extractInitialState(html)
	if got == "" {
		t.Error("extractInitialState should find the state")
	}

	if got != `{"entities":{"users":{}}}` {
		t.Errorf("extractInitialState = %q, want JSON object", got)
	}
}

func TestExtractInitialStateNotFound(t *testing.T) {
	html := `<script>console.log("no state here");</script>`

	got := extractInitialState(html)
	if got != "" {
		t.Errorf("extractInitialState should return empty, got %q", got)
	}
}

func TestParseGraphQLResponse(t *testing.T) {
	tests := []struct {
		name         string
		json         string
		wantUsername string
		wantName     string
		wantBio      string
		wantLocation string
		wantErr      bool
	}{
		{
			name: "full profile",
			json: `{
				"data": {
					"user": {
						"result": {
							"rest_id": "12345",
							"core": {
								"name": "John Doe",
								"screen_name": "johndoe"
							},
							"location": {
								"location": "San Francisco, CA"
							},
							"legacy": {
								"description": "Software engineer at Big Tech",
								"entities": {
									"url": {
										"urls": [
											{"expanded_url": "https://johndoe.com", "display_url": "johndoe.com"}
										]
									}
								}
							}
						}
					}
				}
			}`,
			wantUsername: "johndoe",
			wantName:     "John Doe",
			wantBio:      "Software engineer at Big Tech",
			wantLocation: "San Francisco, CA",
		},
		{
			name: "minimal profile",
			json: `{
				"data": {
					"user": {
						"result": {
							"rest_id": "67890",
							"core": {
								"name": "Jane",
								"screen_name": "jane"
							},
							"location": {},
							"legacy": {}
						}
					}
				}
			}`,
			wantUsername: "jane",
			wantName:     "Jane",
		},
		{
			name: "user not found",
			json: `{
				"data": {
					"user": {
						"result": {}
					}
				}
			}`,
			wantErr: true,
		},
		{
			name:    "invalid json",
			json:    `{invalid}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile, err := parseGraphQLResponse([]byte(tt.json), "https://x.com/test", "test")

			if tt.wantErr {
				if err == nil {
					t.Error("parseGraphQLResponse() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("parseGraphQLResponse() error = %v", err)
			}

			if profile.Username != tt.wantUsername {
				t.Errorf("Username = %q, want %q", profile.Username, tt.wantUsername)
			}
			if profile.DisplayName != tt.wantName {
				t.Errorf("Name = %q, want %q", profile.DisplayName, tt.wantName)
			}
			if tt.wantBio != "" && profile.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", profile.Bio, tt.wantBio)
			}
			if tt.wantLocation != "" && profile.Location != tt.wantLocation {
				t.Errorf("Location = %q, want %q", profile.Location, tt.wantLocation)
			}
		})
	}
}

func TestFilterSamePlatformLinks(t *testing.T) {
	links := []string{
		"https://twitter.com/other",
		"https://x.com/someone",
		"https://github.com/user",
		"https://linkedin.com/in/user",
	}

	filtered := filterSamePlatformLinks(links)

	// Should filter out the twitter.com and x.com links
	if len(filtered) != 2 {
		t.Errorf("filterSamePlatformLinks() returned %d links, want 2", len(filtered))
	}

	for _, link := range filtered {
		if Match(link) {
			t.Errorf("filterSamePlatformLinks() should have filtered %q", link)
		}
	}
}

func TestGetGraphQLFeatures(t *testing.T) {
	features := getGraphQLFeatures()
	if features == nil {
		t.Fatal("getGraphQLFeatures() returned nil")
	}
	if len(features) == 0 {
		t.Error("getGraphQLFeatures() returned empty map")
	}
}

func TestExtractWebsiteFromUser(t *testing.T) {
	tests := []struct {
		name string
		user map[string]any
		want string
	}{
		{
			name: "expanded url",
			user: map[string]any{
				"entities": map[string]any{
					"url": map[string]any{
						"urls": []any{
							map[string]any{
								"expanded_url": "https://example.com/full",
								"display_url":  "example.com",
							},
						},
					},
				},
			},
			want: "https://example.com/full",
		},
		{
			name: "display url fallback",
			user: map[string]any{
				"entities": map[string]any{
					"url": map[string]any{
						"urls": []any{
							map[string]any{
								"display_url": "example.com",
							},
						},
					},
				},
			},
			want: "example.com",
		},
		{
			name: "no entities",
			user: map[string]any{},
			want: "",
		},
		{
			name: "empty urls",
			user: map[string]any{
				"entities": map[string]any{
					"url": map[string]any{
						"urls": []any{},
					},
				},
			},
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractWebsiteFromUser(tt.user)
			if got != tt.want {
				t.Errorf("extractWebsiteFromUser() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetKeys(t *testing.T) {
	m := map[string]any{
		"key1": "value1",
		"key2": "value2",
		"key3": "value3",
	}

	keys := getKeys(m)
	if len(keys) != 3 {
		t.Errorf("getKeys() returned %d keys, want 3", len(keys))
	}
}

func TestIsValidUsername(t *testing.T) {
	tests := []struct {
		name     string
		username string
		want     bool
	}{
		// Valid usernames
		{"simple", "jack", true},
		{"with_underscore", "user_name", true},
		{"with_numbers", "user123", true},
		{"mixed", "User_123", true},
		{"single_char", "x", true},
		{"max_length", "fifteenchars123", true},

		// Invalid usernames
		{"too_short", "", false},
		{"too_long", "thisusernameistoolong", false},
		{"with_dot", "user.name", false},
		{"with_at", "user@name", false},
		{"with_hyphen", "user-name", false},
		{"with_space", "user name", false},
		{"special_chars", "user!name", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidUsername(tt.username); got != tt.want {
				t.Errorf("IsValidUsername(%q) = %v, want %v", tt.username, got, tt.want)
			}
		})
	}
}

func TestIsValidProfileURL(t *testing.T) {
	tests := []struct {
		name string
		url  string
		want bool
	}{
		// Valid profile URLs
		{"simple_twitter", "https://twitter.com/jack", true},
		{"simple_x", "https://x.com/jack", true},
		{"with_underscore", "https://twitter.com/user_name", true},
		{"with_numbers", "https://x.com/user123", true},
		{"with_www", "https://www.twitter.com/username", true},
		{"uppercase", "https://Twitter.com/UserName", true},

		// Invalid - system pages
		{"tos", "https://twitter.com/tos", false},
		{"privacy", "https://x.com/privacy", false},
		{"messages", "https://twitter.com/messages", false},
		{"settings", "https://x.com/settings", false},
		{"search", "https://twitter.com/search", false},
		{"explore", "https://x.com/explore", false},
		{"notifications", "https://twitter.com/notifications", false},
		{"home", "https://x.com/home", false},
		{"login", "https://twitter.com/login", false},
		{"logout", "https://x.com/logout", false},
		{"signup", "https://twitter.com/signup", false},
		{"i_path", "https://x.com/i", false},
		{"compose", "https://twitter.com/compose", false},
		{"intent", "https://x.com/intent", false},
		{"share", "https://twitter.com/share", false},
		{"hashtag", "https://x.com/hashtag", false},
		{"about", "https://twitter.com/about", false},
		{"help", "https://x.com/help", false},
		{"rules", "https://twitter.com/rules", false},
		{"ads", "https://x.com/ads", false},
		{"content", "https://twitter.com/content", false},

		// Invalid - language codes
		{"lang_en", "https://twitter.com/en", false},
		{"lang_es", "https://x.com/es", false},
		{"lang_fr", "https://twitter.com/fr", false},
		{"lang_de", "https://x.com/de", false},
		{"lang_ja", "https://twitter.com/ja", false},

		// Invalid - username violations
		{"too_long", "https://twitter.com/thisusernameistoolong", false},
		{"invalid_chars", "https://x.com/user.name", false},
		{"with_hyphen", "https://twitter.com/user-name", false},

		// Invalid - not Twitter URLs
		{"github", "https://github.com/user", false},
		{"linkedin", "https://linkedin.com/in/user", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsValidProfileURL(tt.url); got != tt.want {
				t.Errorf("IsValidProfileURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
