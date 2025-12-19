package behance

import (
	"context"
	"testing"

	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
)

func TestParseProfile(t *testing.T) {
	html := `
		<!DOCTYPE html>
		<html>
		<head>
			<title>T Scott Stromberg on Behance</title>
			<meta property="og:title" content="T Scott Stromberg on Behance">
			<meta property="og:image" content="https://pps.services.adobe.com/api/profile/CA971E7E67E39C0B0A495EE8@a474269963df7fc3495ffa.e/image/a934fa21-565f-436a-9ab4-86ee95f54b4b/230">
			<script type="application/ld+json">
			{
				"@context": "http://schema.org",
				"@type": "Person",
				"name": "T Scott Stromberg",
				"image": "https://pps.services.adobe.com/api/profile/CA971E7E67E39C0B0A495EE8@a474269963df7fc3495ffa.e/image/a934fa21-565f-436a-9ab4-86ee95f54b4b/230",
				"address": {
					"@type": "PostalAddress",
					"addressLocality": "USA"
				}
			}
			</script>
		</head>
		<body>
			<span class="UserInfo-location">USA</span>
		</body>
		</html>
	`

	c := &Client{}
	p, err := c.parseProfile(context.Background(), html, "https://www.behance.net/tstromberg", "tstromberg")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if p.DisplayName != "T Scott Stromberg" {
		t.Errorf("expected DisplayName 'T Scott Stromberg', got '%s'", p.DisplayName)
	}

	if p.Location != "USA" {
		t.Errorf("expected Location 'USA', got '%s'", p.Location)
	}

	expectedAvatar := "https://pps.services.adobe.com/api/profile/CA971E7E67E39C0B0A495EE8@a474269963df7fc3495ffa.e/image/a934fa21-565f-436a-9ab4-86ee95f54b4b/230"
	if p.AvatarURL != expectedAvatar {
		t.Errorf("expected AvatarURL '%s', got '%s'", expectedAvatar, p.AvatarURL)
	}
}

func TestParseProfileGeneric(t *testing.T) {
	html := `<html><head><title>Behance</title></head><body></body></html>`
	c := &Client{}
	_, err := c.parseProfile(context.Background(), html, "https://www.behance.net/tstromberg", "tstromberg")
	if err != profile.ErrProfileNotFound {
		t.Errorf("expected ErrProfileNotFound for generic page, got %v", err)
	}
}
