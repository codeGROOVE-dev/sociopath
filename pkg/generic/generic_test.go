package generic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestMatch(t *testing.T) {
	// Generic always matches
	tests := []string{
		"https://example.com",
		"https://random-site.org/profile",
		"anything",
	}

	for _, url := range tests {
		if !Match(url) {
			t.Errorf("Match(%q) should always return true", url)
		}
	}
}

func TestAuthRequired(t *testing.T) {
	if AuthRequired() {
		t.Error("Generic should not require auth")
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://example.com", false},
		{"https://localhost", true},
		{"https://127.0.0.1", true},
		{"https://192.168.1.1", true},
		{"https://10.0.0.1", true},
		{"https://169.254.169.254", true},
		{"https://metadata.google.internal", true},
		{"https://metadata.azure.com", true},
		{"https://foo.local", true},
		{"https://foo.internal", true},
		{"https://[::1]", true},
		{"https://172.16.0.1", true},
		{"https://example.com/support", true},
		{"https://example.com/foo/support", true},
		{"https://example.com/supported", false}, // not exactly /support
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			err := validateURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestCleanEmail(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"website@nospamtpope.org", "website@tpope.org"},
		{"contact@NOSPAMexample.com", "contact@example.com"},
		{"user@NoSpAmtest.org", "user@test.org"},
		{"normal@example.com", "normal@example.com"},
		{"test@nospam.nospam.org", "test@.nospam.org"}, // Only removes first occurrence
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := cleanEmail(tt.input)
			if got != tt.want {
				t.Errorf("cleanEmail(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNew(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if client == nil {
		t.Fatal("New() returned nil client")
	}
}

func TestParseHTML_WithEmail(t *testing.T) {
	html := `<html><head><title>Test</title></head><body>
		<p>Contact me at contact@acmecorp.io or backup@acmecorp.net</p>
	</body></html>`

	profile := parseHTML([]byte(html), "https://acmecorp.io")

	if profile.Fields["email"] != "contact@acmecorp.io" {
		t.Errorf("email = %q, want %q", profile.Fields["email"], "contact@acmecorp.io")
	}
}

func TestFetch_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, server.URL)
	if err == nil {
		t.Error("Fetch() expected error for 404, got nil")
	}
}

func TestFetch_BlockedURL(t *testing.T) {
	ctx := context.Background()
	client, err := New(ctx)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.Fetch(ctx, "http://localhost/secret")
	if err == nil {
		t.Error("Fetch() expected error for blocked URL, got nil")
	}
}

func TestParseHTML(t *testing.T) {
	tests := []struct {
		name      string
		html      string
		url       string
		wantTitle string
		wantBio   string
	}{
		{
			name: "full page",
			html: `<html><head>
				<title>Test Page</title>
				<meta name="description" content="A test description">
			</head><body>
				<a href="https://github.com/user">GitHub</a>
				<a href="mailto:user@example.com">Email</a>
			</body></html>`,
			url:       "https://example.com",
			wantTitle: "Test Page",
			wantBio:   "A test description",
		},
		{
			name:      "empty page",
			html:      `<html><head></head><body></body></html>`,
			url:       "https://example.com",
			wantTitle: "",
			wantBio:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profile := parseHTML([]byte(tt.html), tt.url)

			if profile.PageTitle != tt.wantTitle {
				t.Errorf("PageTitle = %q, want %q", profile.PageTitle, tt.wantTitle)
			}
			if profile.Bio != tt.wantBio {
				t.Errorf("Bio = %q, want %q", profile.Bio, tt.wantBio)
			}
		})
	}
}

func TestDedupeLinks(t *testing.T) {
	links := []string{
		"https://github.com/user",
		"https://GITHUB.COM/user/",
		"https://twitter.com/user",
		"https://github.com/user",
	}

	deduped := dedupeLinks(links)
	if len(deduped) != 2 {
		t.Errorf("dedupeLinks() returned %d links, want 2", len(deduped))
	}
}

func TestWithOptions(t *testing.T) {
	ctx := context.Background()

	t.Run("with_cache", func(t *testing.T) {
		client, err := New(ctx, WithHTTPCache(nil))
		if err != nil {
			t.Fatalf("New(WithHTTPCache) error = %v", err)
		}
		if client == nil {
			t.Fatal("New(WithHTTPCache) returned nil")
		}
	})
}

func TestIsBlogPage(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "RSS feed link",
			content: `<link rel="alternate" type="application/rss+xml" href="/feed.xml">`,
			want:    true,
		},
		{
			name:    "Atom feed link",
			content: `<link rel="alternate" type="application/atom+xml" href="/feed.xml">`,
			want:    true,
		},
		{
			name:    "multiple post links",
			content: `<a href="/posts/a">A</a><a href="/posts/b">B</a><a href="/posts/c">C</a>`,
			want:    true,
		},
		{
			name:    "recent posts heading",
			content: `<h2>Recent Posts</h2>`,
			want:    true,
		},
		{
			name:    "latest posts heading",
			content: `<h1>Latest Posts</h1>`,
			want:    true,
		},
		{
			name:    "not a blog",
			content: `<html><body><h1>About Me</h1><p>Hello world</p></body></html>`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBlogPage(tt.content); got != tt.want {
				t.Errorf("isBlogPage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsPostURL(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"/posts/2025/my-article/", true},
		{"/post/hello-world", true},
		{"/blog/2024/post", true},
		{"/article/test", true},
		{"/2024/some-post", true},
		{"/about", false},
		{"/contact", false},
		{"https://example.com/", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := isPostURL(tt.url); got != tt.want {
				t.Errorf("isPostURL(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestExtractBlogPosts(t *testing.T) {
	tests := []struct {
		name      string
		html      string
		baseURL   string
		wantCount int
		wantFirst string
	}{
		{
			name: "choosehappy.dev style",
			html: `<html>
				<head><link rel="alternate" type="application/atom+xml" href="/feed.xml"></head>
				<body>
				<h2>recent posts</h2>
				<ul>
				<li><a href="/posts/2025/llms-doing-the-dirty-blog-work/">Using LLMs to do dirty blog work</a> - 2025-07-07</li>
				<li><a href="/posts/2025/reinstalling-our-home-storage-server/">Reinstalling our home storage server</a> - 2025-06-21</li>
				</ul>
				</body></html>`,
			baseURL:   "https://choosehappy.dev/",
			wantCount: 2,
			wantFirst: "Using LLMs to do dirty blog work",
		},
		{
			name: "article elements",
			html: `<html>
				<head><link rel="alternate" type="application/rss+xml" href="/rss"></head>
				<body>
				<article>
					<a href="/blog/2024/post-one">Post One</a>
					<a href="/blog/2024/post-two">Post Two</a>
				</article>
				</body></html>`,
			baseURL:   "https://example.com/",
			wantCount: 2,
			wantFirst: "Post One",
		},
		{
			name: "hugo microblog style",
			html: `<html>
				<head><link rel="alternate" href="/feed.xml" type="application/rss+xml"></head>
				<body>
				<a href="/2025/12/12/rethinking-sudo.html"><h1>Rethinking sudo with object capabilities</h1></a>
				<time datetime="2025-12-12">2025-12-12</time>
				<a href="/2025/12/02/i-want-you.html"><h1>I want you to understand</h1></a>
				<time datetime="2025-12-02">2025-12-02</time>
				</body></html>`,
			baseURL:   "https://ariadne.space/",
			wantCount: 2,
			wantFirst: "Rethinking sudo with object capabilities",
		},
		{
			name: "not a blog",
			html: `<html><body><h1>About Me</h1><p>Hello world</p>
				<a href="/contact">Contact</a>
				</body></html>`,
			baseURL:   "https://example.com/",
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			posts, _ := extractBlogPosts(tt.html, tt.baseURL)
			if len(posts) != tt.wantCount {
				t.Errorf("extractBlogPosts() returned %d posts, want %d", len(posts), tt.wantCount)
			}
			if tt.wantCount > 0 && len(posts) > 0 && posts[0].Title != tt.wantFirst {
				t.Errorf("first post title = %q, want %q", posts[0].Title, tt.wantFirst)
			}
		})
	}
}

func TestExtractDateFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"/posts/2025/my-article/", "2025-01-01"},
		{"/blog/2024/05/post", "2024-05-01"},
		{"/posts/2023/11/04/article", "2023-11-04"},
		{"/about", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := extractDateFromURL(tt.url); got != tt.want {
				t.Errorf("extractDateFromURL(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestIsBotProtectionPage(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    bool
	}{
		{
			name:    "PyPI client challenge",
			content: `<html><head><title>Client Challenge</title></head><body>Client Challenge JavaScript is disabled</body></html>`,
			want:    true,
		},
		{
			name:    "Cloudflare checking browser",
			content: `<html><body>Checking your browser before accessing the site...</body></html>`,
			want:    true,
		},
		{
			name:    "Cloudflare cf_chl_opt",
			content: `<html><script>var cf_chl_opt = {};</script></html>`,
			want:    true,
		},
		{
			name:    "short JS enable page",
			content: `<html><body>Please enable JavaScript to continue</body></html>`,
			want:    true,
		},
		{
			name:    "verify human",
			content: `<html><body>Please verify you are a human to continue</body></html>`,
			want:    true,
		},
		{
			name:    "normal short page",
			content: `<html><head><title>User</title></head><body>Profile</body></html>`,
			want:    false,
		},
		{
			name:    "normal profile page",
			content: `<html><head><title>John Doe</title><meta name="description" content="Software developer"></head><body><h1>John Doe</h1><p>Hello, I'm a developer from San Francisco.</p></body></html>`,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isBotProtectionPage([]byte(tt.content)); got != tt.want {
				t.Errorf("isBotProtectionPage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseHTML_Blog(t *testing.T) {
	html := `<html>
		<head>
			<title>My Blog</title>
			<meta name="description" content="A personal blog">
			<link rel="alternate" type="application/atom+xml" href="/feed.xml">
		</head>
		<body>
		<h2>recent posts</h2>
		<ul>
		<li><a href="/posts/2025/first-post/">First Post</a> - 2025-01-15</li>
		<li><a href="/posts/2024/second-post/">Second Post</a> - 2024-12-01</li>
		</ul>
		</body></html>`

	p := parseHTML([]byte(html), "https://myblog.com/")

	if p.Platform != "blog" {
		t.Errorf("Platform = %q, want %q", p.Platform, "blog")
	}
	if len(p.Posts) != 2 {
		t.Fatalf("Posts count = %d, want 2", len(p.Posts))
	}
	if p.Posts[0].Title != "First Post" {
		t.Errorf("First post title = %q, want %q", p.Posts[0].Title, "First Post")
	}
	if p.Posts[0].URL != "https://myblog.com/posts/2025/first-post/" {
		t.Errorf("First post URL = %q, want %q", p.Posts[0].URL, "https://myblog.com/posts/2025/first-post/")
	}
}
