package htmlutil

import "testing"

func TestToMarkdown(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "headers",
			html: "<h1>Title</h1><h2>Subtitle</h2>",
			want: "# Title\n\n## Subtitle",
		},
		{
			name: "paragraph",
			html: "<p>Hello world</p>",
			want: "Hello world",
		},
		{
			name: "link",
			html: `<a href="https://example.com">Click here</a>`,
			want: "[Click here](https://example.com)",
		},
		{
			name: "bold",
			html: "<b>bold text</b>",
			want: "**bold text**",
		},
		{
			name: "italic",
			html: "<em>italic text</em>",
			want: "*italic text*",
		},
		{
			name: "removes script",
			html: "<p>before</p><script>alert('x')</script><p>after</p>",
			want: "before\n\nafter",
		},
		{
			name: "removes style",
			html: "<style>.foo{}</style><p>content</p>",
			want: "content",
		},
		{
			name: "list items",
			html: "<ul><li>one</li><li>two</li></ul>",
			want: "- one\n- two",
		},
		{
			name: "html entities",
			html: "&amp; &lt; &gt; &quot;",
			want: "& < > \"",
		},
		{
			name: "empty",
			html: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToMarkdown(tt.html)
			if got != tt.want {
				t.Errorf("ToMarkdown() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTitle(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "title tag",
			html: "<title>My Page</title>",
			want: "My Page",
		},
		{
			name: "og:title",
			html: `<meta property="og:title" content="OG Title">`,
			want: "OG Title",
		},
		{
			name: "h1 fallback",
			html: "<h1>Header Title</h1>",
			want: "Header Title",
		},
		{
			name: "prefers title over og:title",
			html: `<title>Title Tag</title><meta property="og:title" content="OG">`,
			want: "Title Tag",
		},
		{
			name: "empty",
			html: "<p>no title</p>",
			want: "",
		},
		{
			name: "with html entities",
			html: "<title>Tom &amp; Jerry</title>",
			want: "Tom & Jerry",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Title(tt.html)
			if got != tt.want {
				t.Errorf("Title() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDescription(t *testing.T) {
	tests := []struct {
		name string
		html string
		want string
	}{
		{
			name: "meta description",
			html: `<meta name="description" content="Page description">`,
			want: "Page description",
		},
		{
			name: "og:description",
			html: `<meta property="og:description" content="OG description">`,
			want: "OG description",
		},
		{
			name: "prefers meta over og",
			html: `<meta name="description" content="Meta"><meta property="og:description" content="OG">`,
			want: "Meta",
		},
		{
			name: "empty",
			html: "<p>no description</p>",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Description(tt.html)
			if got != tt.want {
				t.Errorf("Description() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSocialLinks(t *testing.T) {
	html := `
		<a href="https://twitter.com/johndoe">Twitter</a>
		<a href="https://linkedin.com/in/johndoe">LinkedIn</a>
		<a href="https://github.com/johndoe">GitHub</a>
		<a href="https://mastodon.social/@johndoe">Mastodon</a>
		<a href="https://bsky.app/profile/johndoe.bsky.social">BlueSky</a>
		<a href="https://example.com">Not social</a>
	`

	links := SocialLinks(html)

	// Should find the social links
	expected := map[string]bool{
		"https://twitter.com/johndoe":                  true,
		"https://linkedin.com/in/johndoe":              true,
		"https://github.com/johndoe":                   true,
		"https://mastodon.social/@johndoe":             true,
		"https://bsky.app/profile/johndoe.bsky.social": true,
	}

	for _, link := range links {
		if !expected[link] {
			t.Logf("found unexpected link: %s", link)
		}
	}

	// Verify we found at least the main ones
	if len(links) < 4 {
		t.Errorf("expected at least 4 social links, got %d: %v", len(links), links)
	}
}

func TestSocialLinksDeduplication(t *testing.T) {
	html := `
		<a href="https://twitter.com/johndoe">Twitter</a>
		<a href="https://twitter.com/johndoe">Twitter again</a>
	`

	links := SocialLinks(html)

	count := 0
	for _, link := range links {
		if link == "https://twitter.com/johndoe" {
			count++
		}
	}

	if count != 1 {
		t.Errorf("expected 1 occurrence, got %d", count)
	}
}
