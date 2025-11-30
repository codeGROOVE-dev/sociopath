package guess

import (
	"testing"

	"github.com/codeGROOVE-dev/sociopath/profile"
)

// TestScoreName tests the name similarity scoring function.
func TestScoreName(t *testing.T) {
	tests := []struct {
		name     string
		nameA    string
		nameB    string
		wantMin  float64 // minimum expected score
		wantMax  float64 // maximum expected score
		hasMatch bool    // should there be a match?
	}{
		{
			name:     "exact match",
			nameA:    "John Doe",
			nameB:    "John Doe",
			wantMin:  1.0,
			wantMax:  1.0,
			hasMatch: true,
		},
		{
			name:     "case insensitive",
			nameA:    "John Doe",
			nameB:    "john doe",
			wantMin:  1.0,
			wantMax:  1.0,
			hasMatch: true,
		},
		{
			name:     "full name vs short name",
			nameA:    "Thomas Strömberg",
			nameB:    "Thom",
			wantMin:  0.6,
			wantMax:  0.8,
			hasMatch: true,
		},
		{
			name:     "name with middle initial",
			nameA:    "David E Worth",
			nameB:    "David Worth",
			wantMin:  0.6,
			wantMax:  0.8,
			hasMatch: true,
		},
		{
			name:     "first name only match",
			nameA:    "Thomas Strömberg",
			nameB:    "Thomas",
			wantMin:  0.4,
			wantMax:  0.7,
			hasMatch: true,
		},
		{
			name:     "last name only match",
			nameA:    "Thomas Strömberg",
			nameB:    "Strömberg",
			wantMin:  0.4,
			wantMax:  0.7,
			hasMatch: true,
		},
		{
			name:     "no match",
			nameA:    "John Doe",
			nameB:    "Jane Smith",
			wantMin:  0.0,
			wantMax:  0.0,
			hasMatch: false,
		},
		{
			name:     "empty names",
			nameA:    "",
			nameB:    "John Doe",
			wantMin:  0.0,
			wantMax:  0.0,
			hasMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreName(tt.nameA, tt.nameB)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("scoreName(%q, %q) = %v, want between %v and %v",
					tt.nameA, tt.nameB, got, tt.wantMin, tt.wantMax)
			}
			if tt.hasMatch && got == 0 {
				t.Errorf("scoreName(%q, %q) = 0, expected a match", tt.nameA, tt.nameB)
			}
			if !tt.hasMatch && got > 0 {
				t.Errorf("scoreName(%q, %q) = %v, expected no match", tt.nameA, tt.nameB, got)
			}
		})
	}
}

// TestScoreLocation tests the location similarity scoring function.
func TestScoreLocation(t *testing.T) {
	tests := []struct {
		name     string
		locA     string
		locB     string
		wantMin  float64
		wantMax  float64
		hasMatch bool
	}{
		{
			name:     "exact match",
			locA:     "San Francisco, CA",
			locB:     "San Francisco, CA",
			wantMin:  1.0,
			wantMax:  1.0,
			hasMatch: true,
		},
		{
			name:     "city only vs full",
			locA:     "San Francisco",
			locB:     "San Francisco, CA",
			wantMin:  0.7,
			wantMax:  0.9,
			hasMatch: true,
		},
		{
			name:     "different cities",
			locA:     "New York",
			locB:     "Los Angeles",
			wantMin:  0.0,
			wantMax:  0.0,
			hasMatch: false,
		},
		{
			name:     "same state different city",
			locA:     "San Francisco, CA",
			locB:     "Los Angeles, CA",
			wantMin:  0.2,
			wantMax:  0.5,
			hasMatch: true,
		},
		{
			name:     "variations of location format",
			locA:     "Carrboro, NC",
			locB:     "Carrboro, North Carolina",
			wantMin:  0.3,
			wantMax:  0.5,
			hasMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreLocation(tt.locA, tt.locB)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("scoreLocation(%q, %q) = %v, want between %v and %v",
					tt.locA, tt.locB, got, tt.wantMin, tt.wantMax)
			}
			if tt.hasMatch && got == 0 {
				t.Errorf("scoreLocation(%q, %q) = 0, expected a match", tt.locA, tt.locB)
			}
			if !tt.hasMatch && got > 0 {
				t.Errorf("scoreLocation(%q, %q) = %v, expected no match", tt.locA, tt.locB, got)
			}
		})
	}
}

// TestScoreBioOverlap tests bio text similarity scoring.
func TestScoreBioOverlap(t *testing.T) {
	tests := []struct {
		name     string
		bioA     string
		bioB     string
		wantMin  float64
		wantMax  float64
		hasMatch bool
	}{
		{
			name:     "exact match",
			bioA:     "Software engineer interested in security and open source",
			bioB:     "Software engineer interested in security and open source",
			wantMin:  0.8,
			wantMax:  1.0,
			hasMatch: true,
		},
		{
			name:     "partial overlap with tech terms",
			bioA:     "Rust developer working on kubernetes and cloud-native tools",
			bioB:     "Cloud-native developer, kubernetes contributor",
			wantMin:  0.3,
			wantMax:  0.7,
			hasMatch: true,
		},
		{
			name:     "minimal overlap",
			bioA:     "I love cats and dogs",
			bioB:     "Pets are great",
			wantMin:  0.0,
			wantMax:  0.2,
			hasMatch: false,
		},
		{
			name:     "hashtag overlap",
			bioA:     "#infosec #security #golang developer",
			bioB:     "Security engineer. #infosec #golang",
			wantMin:  0.4,
			wantMax:  0.8,
			hasMatch: true,
		},
		{
			name:     "company/technology mentions",
			bioA:     "Engineer at Chainguard working on security and supply chain",
			bioB:     "Director at Chainguard, security focused",
			wantMin:  0.3,
			wantMax:  0.7,
			hasMatch: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scoreBioOverlap(tt.bioA, tt.bioB)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("scoreBioOverlap(%q, %q) = %v, want between %v and %v",
					tt.bioA, tt.bioB, got, tt.wantMin, tt.wantMax)
			}
			if tt.hasMatch && got == 0 {
				t.Errorf("scoreBioOverlap(%q, %q) = 0, expected a match", tt.bioA, tt.bioB)
			}
		})
	}
}

// TestScoreMatchIntegration tests the full scoreMatch function with realistic profile data.
func TestScoreMatchIntegration(t *testing.T) {
	tests := []struct {
		name        string
		guessed     *profile.Profile
		known       []*profile.Profile
		candidate   candidateURL
		wantMin     float64
		wantMax     float64
		wantMatches []string // expected match types to be present
	}{
		{
			name: "high confidence - username, name, employer, location match",
			guessed: &profile.Profile{
				Platform: "linkedin",
				URL:      "https://linkedin.com/in/daveworth",
				Username: "daveworth",
				Name:     "David Worth",
				Location: "Denver, CO",
				Fields:   map[string]string{"employer": "Defense Unicorns"},
			},
			known: []*profile.Profile{
				{
					Platform: "github",
					URL:      "https://github.com/daveworth",
					Username: "daveworth",
					Name:     "David E Worth",
					Location: "Denver, Colorado",
					Fields:   map[string]string{"company": "defenseunicorns"},
				},
			},
			candidate: candidateURL{
				username:  "daveworth",
				matchType: "username",
			},
			wantMin:     0.75,
			wantMax:     1.0,
			wantMatches: []string{"username:exact", "name:github", "location:github", "employer:github"},
		},
		{
			name: "name-based LinkedIn guess with employer boost",
			guessed: &profile.Profile{
				Platform: "linkedin",
				URL:      "https://linkedin.com/in/david-e-worth",
				Username: "david-e-worth",
				Name:     "David Worth",
				Fields:   map[string]string{"employer": "Defense Unicorns"},
			},
			known: []*profile.Profile{
				{
					Platform: "github",
					Username: "daveworth",
					Name:     "David E Worth",
					Fields:   map[string]string{"company": "defenseunicorns"},
				},
			},
			candidate: candidateURL{
				username:   "david-e-worth",
				matchType:  "name",
				sourceName: "David E Worth",
			},
			wantMin:     0.75,
			wantMax:     1.0,
			wantMatches: []string{"name:slug", "name:github", "employer:github"},
		},
		{
			name: "medium confidence - username and name match only",
			guessed: &profile.Profile{
				Platform: "twitter",
				Username: "johndoe",
				Name:     "John Doe",
			},
			known: []*profile.Profile{
				{
					Platform: "github",
					Username: "johndoe",
					Name:     "John Doe",
				},
			},
			candidate: candidateURL{
				username:  "johndoe",
				matchType: "username",
			},
			wantMin:     0.5,
			wantMax:     0.7,
			wantMatches: []string{"username:exact", "name:github"},
		},
		{
			name: "cross-platform link detection",
			guessed: &profile.Profile{
				Platform: "mastodon",
				URL:      "https://mastodon.social/@johndoe",
				Username: "johndoe",
				Name:     "John Doe",
			},
			known: []*profile.Profile{
				{
					Platform:    "github",
					Username:    "johndoe",
					Name:        "John Doe",
					SocialLinks: []string{"https://mastodon.social/@johndoe"},
				},
			},
			candidate: candidateURL{
				username:  "johndoe",
				matchType: "username",
			},
			wantMin:     0.8,
			wantMax:     1.0,
			wantMatches: []string{"username:exact", "linked:github"},
		},
		{
			name: "website match boost",
			guessed: &profile.Profile{
				Platform: "twitter",
				Username: "johndoe",
				Name:     "John Doe",
				Website:  "https://example.com",
			},
			known: []*profile.Profile{
				{
					Platform: "github",
					Username: "johndoe",
					Name:     "John Doe",
					Website:  "https://example.com",
				},
			},
			candidate: candidateURL{
				username:  "johndoe",
				matchType: "username",
			},
			wantMin:     0.9,
			wantMax:     1.0,
			wantMatches: []string{"username:exact", "name:github", "website:github"},
		},
		{
			name: "bio overlap detection",
			guessed: &profile.Profile{
				Platform: "twitter",
				Username: "rustdev",
				Name:     "Jane Smith",
				Bio:      "Rust developer, kubernetes contributor, cloud-native enthusiast",
			},
			known: []*profile.Profile{
				{
					Platform: "github",
					Username: "rustdev",
					Name:     "Jane Smith",
					Bio:      "Working on kubernetes and cloud-native tools in Rust",
				},
			},
			candidate: candidateURL{
				username:  "rustdev",
				matchType: "username",
			},
			wantMin:     0.6,
			wantMax:     0.8,
			wantMatches: []string{"username:exact", "name:github", "bio:github"},
		},
		{
			name: "low confidence - short username no other signals",
			guessed: &profile.Profile{
				Platform: "twitter",
				Username: "john",
				Name:     "J. Smith",
			},
			known: []*profile.Profile{
				{
					Platform: "github",
					Username: "john",
					Name:     "John Doe",
				},
			},
			candidate: candidateURL{
				username:  "john",
				matchType: "username",
			},
			wantMin:     0.1,
			wantMax:     0.3,
			wantMatches: []string{"username:exact"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotScore, gotMatches := scoreMatch(tt.guessed, tt.known, tt.candidate)

			if gotScore < tt.wantMin || gotScore > tt.wantMax {
				t.Errorf("scoreMatch() score = %v, want between %v and %v",
					gotScore, tt.wantMin, tt.wantMax)
			}

			// Check that expected match types are present
			matchMap := make(map[string]bool)
			for _, m := range gotMatches {
				matchMap[m] = true
			}

			for _, expectedMatch := range tt.wantMatches {
				if !matchMap[expectedMatch] {
					t.Errorf("scoreMatch() matches = %v, missing expected match %q",
						gotMatches, expectedMatch)
				}
			}

			t.Logf("Score: %.2f, Matches: %v", gotScore, gotMatches)
		})
	}
}

// TestExtractSignificantWords tests the bio keyword extraction.
func TestExtractSignificantWords(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantWords []string // should contain these words
		notWords  []string // should NOT contain these words
	}{
		{
			name:      "filter common words",
			input:     "I am a developer and I love the Rust programming language",
			wantWords: []string{"developer", "love", "rust", "programming", "language"},
			notWords:  []string{"i", "am", "a", "and", "the"},
		},
		{
			name:      "preserve hashtags",
			input:     "Security engineer #infosec #golang #kubernetes",
			wantWords: []string{"security", "engineer", "#infosec", "#golang", "#kubernetes"},
			notWords:  []string{},
		},
		{
			name:      "preserve company names",
			input:     "Working at Google on cloud infrastructure",
			wantWords: []string{"working", "google", "cloud", "infrastructure"},
			notWords:  []string{"at", "on"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSignificantWords(tt.input)
			gotMap := make(map[string]bool)
			for _, word := range got {
				gotMap[word] = true
			}

			for _, want := range tt.wantWords {
				if !gotMap[want] {
					t.Errorf("extractSignificantWords(%q) = %v, missing %q", tt.input, got, want)
				}
			}

			for _, notWant := range tt.notWords {
				if gotMap[notWant] {
					t.Errorf("extractSignificantWords(%q) = %v, should not contain %q", tt.input, got, notWant)
				}
			}
		})
	}
}
