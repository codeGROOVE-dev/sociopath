// Package sociopath provides a unified API for fetching social media profiles.
//
// Basic usage:
//
//	profile, err := sociopath.Fetch(ctx, "https://mastodon.social/@johndoe")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Println(profile.Name, profile.Bio)
//
// For platforms requiring authentication (LinkedIn, Twitter):
//
//	profile, err := sociopath.Fetch(ctx, "https://linkedin.com/in/johndoe",
//	    sociopath.WithCookies(map[string]string{"li_at": "...", "JSESSIONID": "..."}))
//
// Or use platform packages directly:
//
//	import "github.com/codeGROOVE-dev/sociopath/pkg/linkedin"
//	client, _ := linkedin.New(ctx, linkedin.WithBrowserCookies())
//	profile, _ := client.Fetch(ctx, "https://linkedin.com/in/johndoe")
package sociopath

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/codeGROOVE-dev/sociopath/pkg/arstechnica"
	"github.com/codeGROOVE-dev/sociopath/pkg/bilibili"
	"github.com/codeGROOVE-dev/sociopath/pkg/bluesky"
	"github.com/codeGROOVE-dev/sociopath/pkg/bugcrowd"
	"github.com/codeGROOVE-dev/sociopath/pkg/codeberg"
	"github.com/codeGROOVE-dev/sociopath/pkg/crates"
	"github.com/codeGROOVE-dev/sociopath/pkg/csdn"
	"github.com/codeGROOVE-dev/sociopath/pkg/devto"
	"github.com/codeGROOVE-dev/sociopath/pkg/disqus"
	"github.com/codeGROOVE-dev/sociopath/pkg/dockerhub"
	"github.com/codeGROOVE-dev/sociopath/pkg/douban"
	"github.com/codeGROOVE-dev/sociopath/pkg/generic"
	"github.com/codeGROOVE-dev/sociopath/pkg/gitee"
	"github.com/codeGROOVE-dev/sociopath/pkg/github"
	"github.com/codeGROOVE-dev/sociopath/pkg/gitlab"
	"github.com/codeGROOVE-dev/sociopath/pkg/goodreads"
	"github.com/codeGROOVE-dev/sociopath/pkg/google"
	"github.com/codeGROOVE-dev/sociopath/pkg/gravatar"
	"github.com/codeGROOVE-dev/sociopath/pkg/guess"
	"github.com/codeGROOVE-dev/sociopath/pkg/habr"
	"github.com/codeGROOVE-dev/sociopath/pkg/hackernews"
	"github.com/codeGROOVE-dev/sociopath/pkg/hackerone"
	"github.com/codeGROOVE-dev/sociopath/pkg/hashnode"
	"github.com/codeGROOVE-dev/sociopath/pkg/hexpm"
	"github.com/codeGROOVE-dev/sociopath/pkg/holopin"
	"github.com/codeGROOVE-dev/sociopath/pkg/httpcache"
	"github.com/codeGROOVE-dev/sociopath/pkg/huggingface"
	"github.com/codeGROOVE-dev/sociopath/pkg/instagram"
	"github.com/codeGROOVE-dev/sociopath/pkg/intensedebate"
	"github.com/codeGROOVE-dev/sociopath/pkg/juejin"
	"github.com/codeGROOVE-dev/sociopath/pkg/keybase"
	"github.com/codeGROOVE-dev/sociopath/pkg/leetcode"
	"github.com/codeGROOVE-dev/sociopath/pkg/linkedin"
	"github.com/codeGROOVE-dev/sociopath/pkg/linktree"
	"github.com/codeGROOVE-dev/sociopath/pkg/lobsters"
	"github.com/codeGROOVE-dev/sociopath/pkg/mailru"
	"github.com/codeGROOVE-dev/sociopath/pkg/mastodon"
	"github.com/codeGROOVE-dev/sociopath/pkg/medium"
	"github.com/codeGROOVE-dev/sociopath/pkg/microblog"
	"github.com/codeGROOVE-dev/sociopath/pkg/orcid"
	"github.com/codeGROOVE-dev/sociopath/pkg/profile"
	"github.com/codeGROOVE-dev/sociopath/pkg/qiita"
	"github.com/codeGROOVE-dev/sociopath/pkg/reddit"
	"github.com/codeGROOVE-dev/sociopath/pkg/rubygems"
	"github.com/codeGROOVE-dev/sociopath/pkg/sessionize"
	"github.com/codeGROOVE-dev/sociopath/pkg/slideshare"
	"github.com/codeGROOVE-dev/sociopath/pkg/stackoverflow"
	"github.com/codeGROOVE-dev/sociopath/pkg/steam"
	"github.com/codeGROOVE-dev/sociopath/pkg/strava"
	"github.com/codeGROOVE-dev/sociopath/pkg/substack"
	"github.com/codeGROOVE-dev/sociopath/pkg/tiktok"
	"github.com/codeGROOVE-dev/sociopath/pkg/twitch"
	"github.com/codeGROOVE-dev/sociopath/pkg/twitter"
	"github.com/codeGROOVE-dev/sociopath/pkg/v2ex"
	"github.com/codeGROOVE-dev/sociopath/pkg/velog"
	"github.com/codeGROOVE-dev/sociopath/pkg/vkontakte"
	"github.com/codeGROOVE-dev/sociopath/pkg/weibo"
	"github.com/codeGROOVE-dev/sociopath/pkg/youtube"
	"github.com/codeGROOVE-dev/sociopath/pkg/zenn"
)

type (
	// Profile re-exports profile.Profile for convenience.
	Profile = profile.Profile
	// HTTPCache re-exports httpcache.Cache for convenience.
	HTTPCache = httpcache.Cache
)

// Re-export common errors.
var (
	ErrAuthRequired    = profile.ErrAuthRequired
	ErrNoCookies       = profile.ErrNoCookies
	ErrProfileNotFound = profile.ErrProfileNotFound
	ErrRateLimited     = profile.ErrRateLimited
)

// Option configures a Fetch call.
type Option func(*config)

//nolint:govet // fieldalignment: intentional layout for readability
type config struct {
	cache          httpcache.Cacher
	cookies        map[string]string
	logger         *slog.Logger
	githubToken    string
	browserCookies bool
	emailHints     []string // Email addresses to associate with profiles
}

// WithCookies sets explicit cookie values for authenticated platforms.
func WithCookies(cookies map[string]string) Option {
	return func(c *config) { c.cookies = cookies }
}

// WithBrowserCookies enables reading cookies from browser stores.
func WithBrowserCookies() Option {
	return func(c *config) { c.browserCookies = true }
}

// WithHTTPCache sets the HTTP cache for responses.
func WithHTTPCache(httpCache httpcache.Cacher) Option {
	return func(c *config) { c.cache = httpCache }
}

// WithLogger sets a custom logger.
func WithLogger(logger *slog.Logger) Option {
	return func(c *config) { c.logger = logger }
}

// WithGitHubToken sets the GitHub API token for authenticated requests.
func WithGitHubToken(token string) Option {
	return func(c *config) { c.githubToken = token }
}

// WithEmailHints provides email addresses to associate with profiles.
// These emails are stored in Fields["email_hints"] and can be used for
// additional lookups (Gravatar, Google GAIA ID resolution, etc.).
func WithEmailHints(emails ...string) Option {
	return func(c *config) { c.emailHints = append(c.emailHints, emails...) }
}

// Fetch retrieves a profile from the given URL.
// The platform is automatically detected from the URL.
func Fetch(ctx context.Context, url string, opts ...Option) (*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	var p *profile.Profile //nolint:varnamelen // short name is clear in this switch context
	var err error

	// Try each platform's Match function in order of specificity
	// Note: Order matters! More specific patterns should come before generic ones.
	// TikTok must come before Mastodon because Mastodon matches /@username pattern.
	// Substack must come before generic because it has specific domain pattern.
	switch {
	case linkedin.Match(url):
		p, err = fetchLinkedIn(ctx, url, cfg)
	case twitter.Match(url):
		p, err = fetchTwitter(ctx, url, cfg)
	case linktree.Match(url):
		p, err = fetchLinktree(ctx, url, cfg)
	case github.Match(url):
		p, err = fetchGitHub(ctx, url, cfg)
	case medium.Match(url):
		p, err = fetchMedium(ctx, url, cfg)
	case microblog.Match(url):
		p, err = fetchMicroblog(ctx, url, cfg)
	case reddit.Match(url):
		p, err = fetchReddit(ctx, url, cfg)
	case youtube.Match(url):
		p, err = fetchYouTube(ctx, url, cfg)
	case substack.Match(url):
		p, err = fetchSubstack(ctx, url, cfg)
	case bilibili.Match(url):
		p, err = fetchBilibili(ctx, url, cfg)
	case codeberg.Match(url):
		p, err = fetchCodeberg(ctx, url, cfg)
	case bluesky.Match(url):
		p, err = fetchBlueSky(ctx, url, cfg)
	case devto.Match(url):
		p, err = fetchDevTo(ctx, url, cfg)
	case stackoverflow.Match(url):
		p, err = fetchStackOverflow(ctx, url, cfg)
	case habr.Match(url):
		p, err = fetchHabr(ctx, url, cfg)
	case instagram.Match(url):
		p, err = fetchInstagram(ctx, url, cfg)
	case keybase.Match(url):
		p, err = fetchKeybase(ctx, url, cfg)
	case crates.Match(url):
		p, err = fetchCrates(ctx, url, cfg)
	case disqus.Match(url):
		p, err = fetchDisqus(ctx, url, cfg)
	case intensedebate.Match(url):
		p, err = fetchIntenseDebate(ctx, url, cfg)
	case dockerhub.Match(url):
		p, err = fetchDockerHub(ctx, url, cfg)
	case gitlab.Match(url):
		p, err = fetchGitLab(ctx, url, cfg)
	case tiktok.Match(url):
		p, err = fetchTikTok(ctx, url, cfg)
	case vkontakte.Match(url):
		p, err = fetchVKontakte(ctx, url, cfg)
	case weibo.Match(url):
		p, err = fetchWeibo(ctx, url, cfg)
	case mailru.Match(url):
		p, err = fetchMailRu(ctx, url, cfg)
	case google.Match(url):
		p, err = fetchGoogle(ctx, url, cfg)
	case gravatar.Match(url):
		p, err = fetchGravatar(ctx, url, cfg)
	case hackernews.Match(url):
		p, err = fetchHackerNews(ctx, url, cfg)
	case hackerone.Match(url):
		p, err = fetchHackerOne(ctx, url, cfg)
	case bugcrowd.Match(url):
		p, err = fetchBugcrowd(ctx, url, cfg)
	case lobsters.Match(url):
		p, err = fetchLobsters(ctx, url, cfg)
	case arstechnica.Match(url):
		p, err = fetchArsTechnica(ctx, url, cfg)
	case sessionize.Match(url):
		p, err = fetchSessionize(ctx, url, cfg)
	case slideshare.Match(url):
		p, err = fetchSlideshare(ctx, url, cfg)
	case strava.Match(url):
		p, err = fetchStrava(ctx, url, cfg)
	case douban.Match(url):
		p, err = fetchDouban(ctx, url, cfg)
	case juejin.Match(url):
		p, err = fetchJuejin(ctx, url, cfg)
	case csdn.Match(url):
		p, err = fetchCSDN(ctx, url, cfg)
	case v2ex.Match(url):
		p, err = fetchV2EX(ctx, url, cfg)
	case gitee.Match(url):
		p, err = fetchGitee(ctx, url, cfg)
	case velog.Match(url):
		p, err = fetchVelog(ctx, url, cfg)
	case qiita.Match(url):
		p, err = fetchQiita(ctx, url, cfg)
	case zenn.Match(url):
		p, err = fetchZenn(ctx, url, cfg)
	case hashnode.Match(url):
		p, err = fetchHashnode(ctx, url, cfg)
	case orcid.Match(url):
		p, err = fetchORCID(ctx, url, cfg)
	case hexpm.Match(url):
		p, err = fetchHexpm(ctx, url, cfg)
	case twitch.Match(url):
		p, err = fetchTwitch(ctx, url, cfg)
	case steam.Match(url):
		p, err = fetchSteam(ctx, url, cfg)
	case leetcode.Match(url):
		p, err = fetchLeetCode(ctx, url, cfg)
	case goodreads.Match(url):
		p, err = fetchGoodreads(ctx, url, cfg)
	case rubygems.Match(url):
		p, err = fetchRubyGems(ctx, url, cfg)
	case huggingface.Match(url):
		p, err = fetchHuggingFace(ctx, url, cfg)
	case holopin.Match(url):
		p, err = fetchHolopin(ctx, url, cfg)
	case mastodon.Match(url):
		p, err = fetchMastodon(ctx, url, cfg)
	default:
		p, err = fetchGeneric(ctx, url, cfg)
	}

	// Apply email hints to the profile
	if err == nil && p != nil && len(cfg.emailHints) > 0 {
		applyEmailHints(p, cfg.emailHints)
	}

	return p, err
}

// applyEmailHints adds email addresses to the profile's Fields.
func applyEmailHints(p *profile.Profile, emails []string) {
	if p.Fields == nil {
		p.Fields = make(map[string]string)
	}
	for i, email := range emails {
		key := "email"
		if i > 0 {
			key = fmt.Sprintf("email_%d", i+1)
		}
		// Don't overwrite existing email fields
		if _, exists := p.Fields[key]; !exists {
			p.Fields[key] = email
		}
	}
}

func fetchLinkedIn(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []linkedin.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, linkedin.WithCookies(cfg.cookies))
	}
	if cfg.browserCookies {
		opts = append(opts, linkedin.WithBrowserCookies())
	}
	if cfg.cache != nil {
		opts = append(opts, linkedin.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, linkedin.WithLogger(cfg.logger))
	}

	client, err := linkedin.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTwitter(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []twitter.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, twitter.WithCookies(cfg.cookies))
	}
	if cfg.browserCookies {
		opts = append(opts, twitter.WithBrowserCookies())
	}
	if cfg.cache != nil {
		opts = append(opts, twitter.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, twitter.WithLogger(cfg.logger))
	}

	client, err := twitter.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchMastodon(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []mastodon.Option
	if cfg.cache != nil {
		opts = append(opts, mastodon.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, mastodon.WithLogger(cfg.logger))
	}

	client, err := mastodon.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchBlueSky(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []bluesky.Option
	if cfg.cache != nil {
		opts = append(opts, bluesky.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, bluesky.WithLogger(cfg.logger))
	}

	client, err := bluesky.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDevTo(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []devto.Option
	if cfg.cache != nil {
		opts = append(opts, devto.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, devto.WithLogger(cfg.logger))
	}

	client, err := devto.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchStackOverflow(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []stackoverflow.Option
	if cfg.cache != nil {
		opts = append(opts, stackoverflow.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, stackoverflow.WithLogger(cfg.logger))
	}

	client, err := stackoverflow.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHabr(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []habr.Option
	if cfg.cache != nil {
		opts = append(opts, habr.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, habr.WithLogger(cfg.logger))
	}

	client, err := habr.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchInstagram(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []instagram.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, instagram.WithCookies(cfg.cookies))
	}

	client, err := instagram.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchKeybase(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []keybase.Option
	if cfg.cache != nil {
		opts = append(opts, keybase.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, keybase.WithLogger(cfg.logger))
	}

	client, err := keybase.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchCrates(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []crates.Option
	if cfg.cache != nil {
		opts = append(opts, crates.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, crates.WithLogger(cfg.logger))
	}

	client, err := crates.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDisqus(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []disqus.Option
	if cfg.cache != nil {
		opts = append(opts, disqus.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, disqus.WithLogger(cfg.logger))
	}

	client, err := disqus.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchIntenseDebate(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []intensedebate.Option
	if cfg.cache != nil {
		opts = append(opts, intensedebate.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, intensedebate.WithLogger(cfg.logger))
	}

	client, err := intensedebate.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDockerHub(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []dockerhub.Option
	if cfg.cache != nil {
		opts = append(opts, dockerhub.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, dockerhub.WithLogger(cfg.logger))
	}

	client, err := dockerhub.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGitLab(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []gitlab.Option
	if cfg.cache != nil {
		opts = append(opts, gitlab.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, gitlab.WithLogger(cfg.logger))
	}

	client, err := gitlab.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTikTok(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []tiktok.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, tiktok.WithCookies(cfg.cookies))
	}
	if cfg.cache != nil {
		opts = append(opts, tiktok.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, tiktok.WithLogger(cfg.logger))
	}

	client, err := tiktok.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchVKontakte(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []vkontakte.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, vkontakte.WithCookies(cfg.cookies))
	}
	if cfg.cache != nil {
		opts = append(opts, vkontakte.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, vkontakte.WithLogger(cfg.logger))
	}

	client, err := vkontakte.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchWeibo(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []weibo.Option
	if len(cfg.cookies) > 0 {
		opts = append(opts, weibo.WithCookies(cfg.cookies))
	}
	if cfg.browserCookies {
		opts = append(opts, weibo.WithBrowserCookies())
	}
	if cfg.cache != nil {
		opts = append(opts, weibo.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, weibo.WithLogger(cfg.logger))
	}

	client, err := weibo.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchLinktree(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []linktree.Option
	if cfg.cache != nil {
		opts = append(opts, linktree.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, linktree.WithLogger(cfg.logger))
	}

	client, err := linktree.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGitHub(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []github.Option
	if cfg.cache != nil {
		opts = append(opts, github.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, github.WithLogger(cfg.logger))
	}
	if cfg.githubToken != "" {
		opts = append(opts, github.WithToken(cfg.githubToken))
	}

	client, err := github.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGoogle(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []google.Option
	if cfg.cache != nil {
		opts = append(opts, google.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, google.WithLogger(cfg.logger))
	}

	client, err := google.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGravatar(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []gravatar.Option
	if cfg.cache != nil {
		opts = append(opts, gravatar.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, gravatar.WithLogger(cfg.logger))
	}

	client, err := gravatar.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchMailRu(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []mailru.Option
	if cfg.cache != nil {
		opts = append(opts, mailru.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, mailru.WithLogger(cfg.logger))
	}

	client, err := mailru.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchMedium(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []medium.Option
	if cfg.cache != nil {
		opts = append(opts, medium.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, medium.WithLogger(cfg.logger))
	}

	client, err := medium.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchMicroblog(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []microblog.Option
	if cfg.cache != nil {
		opts = append(opts, microblog.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, microblog.WithLogger(cfg.logger))
	}

	client, err := microblog.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchReddit(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []reddit.Option
	if cfg.cache != nil {
		opts = append(opts, reddit.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, reddit.WithLogger(cfg.logger))
	}

	client, err := reddit.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchYouTube(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []youtube.Option
	if cfg.cache != nil {
		opts = append(opts, youtube.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, youtube.WithLogger(cfg.logger))
	}

	client, err := youtube.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSubstack(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []substack.Option
	if cfg.cache != nil {
		opts = append(opts, substack.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, substack.WithLogger(cfg.logger))
	}

	client, err := substack.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchBilibili(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []bilibili.Option
	if cfg.cache != nil {
		opts = append(opts, bilibili.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, bilibili.WithLogger(cfg.logger))
	}

	client, err := bilibili.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchCodeberg(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []codeberg.Option
	if cfg.cache != nil {
		opts = append(opts, codeberg.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, codeberg.WithLogger(cfg.logger))
	}

	client, err := codeberg.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHackerNews(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hackernews.Option
	if cfg.cache != nil {
		opts = append(opts, hackernews.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hackernews.WithLogger(cfg.logger))
	}

	client, err := hackernews.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHackerOne(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hackerone.Option
	if cfg.cache != nil {
		opts = append(opts, hackerone.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hackerone.WithLogger(cfg.logger))
	}

	client, err := hackerone.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchBugcrowd(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []bugcrowd.Option
	if cfg.cache != nil {
		opts = append(opts, bugcrowd.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, bugcrowd.WithLogger(cfg.logger))
	}

	client, err := bugcrowd.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchLobsters(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []lobsters.Option
	if cfg.cache != nil {
		opts = append(opts, lobsters.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, lobsters.WithLogger(cfg.logger))
	}

	client, err := lobsters.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchArsTechnica(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []arstechnica.Option
	if cfg.logger != nil {
		opts = append(opts, arstechnica.WithLogger(cfg.logger))
	}

	client, err := arstechnica.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSessionize(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []sessionize.Option
	if cfg.cache != nil {
		opts = append(opts, sessionize.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, sessionize.WithLogger(cfg.logger))
	}

	client, err := sessionize.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSlideshare(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []slideshare.Option
	if cfg.cache != nil {
		opts = append(opts, slideshare.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, slideshare.WithLogger(cfg.logger))
	}

	client, err := slideshare.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchStrava(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []strava.Option
	if cfg.cache != nil {
		opts = append(opts, strava.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, strava.WithLogger(cfg.logger))
	}

	client, err := strava.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchDouban(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []douban.Option
	if cfg.cache != nil {
		opts = append(opts, douban.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, douban.WithLogger(cfg.logger))
	}

	client, err := douban.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchJuejin(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []juejin.Option
	if cfg.cache != nil {
		opts = append(opts, juejin.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, juejin.WithLogger(cfg.logger))
	}

	client, err := juejin.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchCSDN(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []csdn.Option
	if cfg.cache != nil {
		opts = append(opts, csdn.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, csdn.WithLogger(cfg.logger))
	}

	client, err := csdn.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchV2EX(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []v2ex.Option
	if cfg.cache != nil {
		opts = append(opts, v2ex.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, v2ex.WithLogger(cfg.logger))
	}

	client, err := v2ex.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGitee(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []gitee.Option
	if cfg.cache != nil {
		opts = append(opts, gitee.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, gitee.WithLogger(cfg.logger))
	}

	client, err := gitee.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchVelog(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []velog.Option
	if cfg.cache != nil {
		opts = append(opts, velog.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, velog.WithLogger(cfg.logger))
	}

	client, err := velog.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchQiita(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []qiita.Option
	if cfg.cache != nil {
		opts = append(opts, qiita.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, qiita.WithLogger(cfg.logger))
	}

	client, err := qiita.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchZenn(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []zenn.Option
	if cfg.cache != nil {
		opts = append(opts, zenn.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, zenn.WithLogger(cfg.logger))
	}

	client, err := zenn.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHashnode(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hashnode.Option
	if cfg.cache != nil {
		opts = append(opts, hashnode.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hashnode.WithLogger(cfg.logger))
	}

	client, err := hashnode.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchORCID(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []orcid.Option
	if cfg.cache != nil {
		opts = append(opts, orcid.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, orcid.WithLogger(cfg.logger))
	}

	client, err := orcid.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHexpm(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []hexpm.Option
	if cfg.cache != nil {
		opts = append(opts, hexpm.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, hexpm.WithLogger(cfg.logger))
	}

	client, err := hexpm.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchTwitch(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []twitch.Option
	if cfg.cache != nil {
		opts = append(opts, twitch.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, twitch.WithLogger(cfg.logger))
	}

	client, err := twitch.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchSteam(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []steam.Option
	if cfg.cache != nil {
		opts = append(opts, steam.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, steam.WithLogger(cfg.logger))
	}

	client, err := steam.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchLeetCode(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []leetcode.Option
	if cfg.cache != nil {
		opts = append(opts, leetcode.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, leetcode.WithLogger(cfg.logger))
	}

	client, err := leetcode.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGoodreads(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []goodreads.Option
	if cfg.cache != nil {
		opts = append(opts, goodreads.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, goodreads.WithLogger(cfg.logger))
	}

	client, err := goodreads.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchRubyGems(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []rubygems.Option
	if cfg.cache != nil {
		opts = append(opts, rubygems.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, rubygems.WithLogger(cfg.logger))
	}

	client, err := rubygems.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHuggingFace(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []huggingface.Option
	if cfg.cache != nil {
		opts = append(opts, huggingface.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, huggingface.WithLogger(cfg.logger))
	}

	client, err := huggingface.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchHolopin(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []holopin.Option
	if cfg.cache != nil {
		opts = append(opts, holopin.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, holopin.WithLogger(cfg.logger))
	}

	client, err := holopin.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

func fetchGeneric(ctx context.Context, url string, cfg *config) (*profile.Profile, error) {
	var opts []generic.Option
	if cfg.cache != nil {
		opts = append(opts, generic.WithHTTPCache(cfg.cache))
	}
	if cfg.logger != nil {
		opts = append(opts, generic.WithLogger(cfg.logger))
	}

	client, err := generic.New(ctx, opts...)
	if err != nil {
		return nil, err
	}
	return client.Fetch(ctx, url)
}

// FetchRecursive fetches a profile and recursively fetches all social links found.
// It returns all discovered profiles, avoiding duplicates by tracking visited URLs.
// Only links that match known social media platforms are followed.
// For platforms with single-account-per-person assumption (GitHub, LinkedIn, Twitter, etc.),
// it skips recursing into additional profiles from the same platform.
func FetchRecursive(ctx context.Context, url string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	visited := make(map[string]bool)
	var profiles []*profile.Profile
	initialPlatform := "" // Track the platform we started from

	type queueItem struct {
		url   string
		depth int
	}
	const maxDepth = 3
	const maxLinksPerPage = 8

	queue := []queueItem{{url: url, depth: 0}}
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		// Resolve redirects before fetching
		item.url = resolveURLRedirects(ctx, item.url, cfg.logger)

		normalizedURL := normalizeURL(item.url)
		if visited[normalizedURL] {
			continue
		}
		visited[normalizedURL] = true

		cfg.logger.InfoContext(ctx, "fetching profile", "url", item.url, "depth", item.depth, "visited", len(visited))

		p, err := Fetch(ctx, item.url, opts...)
		if err != nil {
			// For auth-required platforms, try generic parser on any error (except LinkedIn)
			// LinkedIn's generic HTML contains dozens of "People Also Viewed" links that cause runaway crawling
			tryGeneric := (twitter.Match(item.url) || instagram.Match(item.url) ||
				tiktok.Match(item.url) || vkontakte.Match(item.url)) && !linkedin.Match(item.url)

			if !tryGeneric {
				cfg.logger.WarnContext(ctx, "failed to fetch profile", "url", item.url, "error", err)
				// If it's an auth-related error, add a stub profile with the error
				if errors.Is(err, profile.ErrNoCookies) || errors.Is(err, profile.ErrAuthRequired) {
					profiles = append(profiles, &profile.Profile{
						Platform: PlatformForURL(item.url),
						URL:      item.url,
						Error:    "login required",
					})
				}
				continue
			}

			cfg.logger.InfoContext(ctx, "fetch failed, trying generic parser", "url", item.url, "error", err)
			p, err = fetchGeneric(ctx, item.url, cfg)
			if err != nil {
				cfg.logger.WarnContext(ctx, "generic fetch also failed", "url", item.url, "error", err)
				continue
			}
		}
		profiles = append(profiles, p)

		// Remember the platform we started from (depth 0)
		if item.depth == 0 {
			initialPlatform = p.Platform
		}

		// Don't crawl further if we've hit max depth
		if item.depth >= maxDepth {
			continue
		}

		// From generic pages, only follow known social platform links to avoid runaway crawling
		onlyKnownPlatforms := p.Platform == "website"

		// Collect links to queue, then limit
		var linksToQueue []string

		// Queue social links for crawling
		for _, link := range p.SocialLinks {
			if !visited[normalizeURL(link)] && isValidProfileURL(link) {
				// Skip links that are the same platform as our initial URL (single-account-per-person platforms)
				if isSingleAccountPlatform(initialPlatform) && platformMatches(link, initialPlatform) {
					continue
				}

				// For generic pages, only follow if it's a known social platform or same-domain contact/about page
				if !onlyKnownPlatforms || isSocialPlatform(link) || isSameDomainContactPage(link, item.url) {
					linksToQueue = append(linksToQueue, link)
				}
			}
		}

		// Also queue website if present
		if p.Website != "" && !visited[normalizeURL(p.Website)] {
			linksToQueue = append(linksToQueue, p.Website)
		}

		// Queue links from Fields map (sorted for deterministic iteration order)
		keys := make([]string, 0, len(p.Fields))
		for k := range p.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := p.Fields[k]
			if isLikelySocialURL(k, v) && !visited[normalizeURL(v)] {
				linksToQueue = append(linksToQueue, v)
			}
		}

		// Limit links per page to avoid explosion
		if len(linksToQueue) > maxLinksPerPage {
			linksToQueue = linksToQueue[:maxLinksPerPage]
		}

		// Deduplicate links (redirects are resolved when URLs are fetched from queue)
		linksToQueue = dedupeLinks(linksToQueue, visited)

		for _, link := range linksToQueue {
			queue = append(queue, queueItem{url: link, depth: item.depth + 1})
		}
	}

	return profiles, nil
}

// isValidProfileURL filters out URLs that are not actual user profiles.
// Delegates to platform-specific validators when available.
func isValidProfileURL(urlStr string) bool {
	// Use platform-specific validation for Twitter/X
	if twitter.Match(urlStr) {
		return twitter.IsValidProfileURL(urlStr)
	}

	// Other platforms: no filtering for now
	return true
}

// isSocialPlatform returns true if the URL matches a known social media platform.
func isSocialPlatform(url string) bool {
	return linkedin.Match(url) ||
		twitter.Match(url) ||
		linktree.Match(url) ||
		github.Match(url) ||
		gitlab.Match(url) ||
		codeberg.Match(url) ||
		google.Match(url) ||
		gravatar.Match(url) ||
		mailru.Match(url) ||
		medium.Match(url) ||
		microblog.Match(url) ||
		reddit.Match(url) ||
		youtube.Match(url) ||
		substack.Match(url) ||
		weibo.Match(url) ||
		strings.Contains(strings.ToLower(url), "zhihu.com") ||
		bilibili.Match(url) ||
		bluesky.Match(url) ||
		devto.Match(url) ||
		stackoverflow.Match(url) ||
		habr.Match(url) ||
		instagram.Match(url) ||
		tiktok.Match(url) ||
		vkontakte.Match(url) ||
		keybase.Match(url) ||
		crates.Match(url) ||
		dockerhub.Match(url) ||
		mastodon.Match(url) ||
		hackerone.Match(url) ||
		bugcrowd.Match(url) ||
		holopin.Match(url)
}

// isSameDomainContactPage returns true if the link is a contact/about page on the same domain as baseURL.
func isSameDomainContactPage(link, baseURL string) bool {
	linkLower := strings.ToLower(link)
	baseLower := strings.ToLower(baseURL)

	// Extract domains (simple approach - get hostname)
	getDomain := func(url string) string {
		url = strings.TrimPrefix(url, "https://")
		url = strings.TrimPrefix(url, "http://")
		url = strings.TrimPrefix(url, "www.")
		if idx := strings.Index(url, "/"); idx >= 0 {
			url = url[:idx]
		}
		return url
	}

	linkDomain := getDomain(linkLower)
	baseDomain := getDomain(baseLower)

	// Only follow if same domain
	if linkDomain != baseDomain {
		return false
	}

	// Check if it looks like a contact/about page
	contactPaths := []string{"/about", "/contact", "/links", "/connect", "/socials"}
	for _, path := range contactPaths {
		if strings.Contains(linkLower, path) {
			return true
		}
	}

	return false
}

// normalizeURL normalizes a URL for deduplication (removes trailing slash, lowercases host).
func normalizeURL(url string) string {
	url = strings.TrimSuffix(url, "/")
	url = strings.TrimPrefix(url, "https://")
	url = strings.TrimPrefix(url, "http://")
	url = strings.TrimPrefix(url, "www.")
	return strings.ToLower(url)
}

// resolveURLRedirects resolves any redirects for a URL and logs if changed.
func resolveURLRedirects(ctx context.Context, url string, logger *slog.Logger) string {
	resolved := httpcache.ResolveRedirects(ctx, url, logger)
	if resolved != url {
		logger.InfoContext(ctx, "resolved redirect", "original", url, "resolved", resolved)
	}
	return resolved
}

// dedupeLinks removes duplicates from a list of links, considering already-visited URLs.
func dedupeLinks(links []string, visited map[string]bool) []string {
	var result []string
	seen := make(map[string]bool)

	// Copy visited into seen to avoid duplicates with already-visited URLs
	for k := range visited {
		seen[k] = true
	}

	for _, link := range links {
		normalized := normalizeURL(link)
		if seen[normalized] {
			continue
		}
		seen[normalized] = true
		result = append(result, link)
	}

	return result
}

// isLikelySocialURL checks if a field value looks like a social media URL worth crawling.
func isLikelySocialURL(key, value string) bool {
	if !strings.HasPrefix(value, "http") {
		return false
	}
	// Known social field keys
	socialKeys := []string{"twitter", "linkedin", "github", "instagram", "youtube", "tiktok", "mastodon", "bluesky", "website"}
	for _, k := range socialKeys {
		if strings.Contains(strings.ToLower(key), k) {
			return true
		}
	}
	return false
}

// isSingleAccountPlatform returns true for platforms where users typically have a single account.
func isSingleAccountPlatform(platform string) bool {
	switch platform {
	case "github", "codeberg", "linkedin", "twitter", "reddit", "youtube",
		"stackoverflow", "bluesky", "mastodon", "medium",
		"instagram", "tiktok", "vkontakte":
		return true
	default:
		return false
	}
}

// PlatformForURL returns the platform name for a URL, or "website" if unknown.
// This uses the same matching logic as Fetch() to ensure consistency.
func PlatformForURL(url string) string {
	switch {
	case linkedin.Match(url):
		return "linkedin"
	case twitter.Match(url):
		return "twitter"
	case linktree.Match(url):
		return "linktree"
	case github.Match(url):
		return "github"
	case gitlab.Match(url):
		return "gitlab"
	case codeberg.Match(url):
		return "codeberg"
	case google.Match(url):
		return "google"
	case medium.Match(url):
		return "medium"
	case microblog.Match(url):
		return "microblog"
	case reddit.Match(url):
		return "reddit"
	case youtube.Match(url):
		return "youtube"
	case substack.Match(url):
		return "substack"
	case bilibili.Match(url):
		return "bilibili"
	case bluesky.Match(url):
		return "bluesky"
	case devto.Match(url):
		return "devto"
	case stackoverflow.Match(url):
		return "stackoverflow"
	case habr.Match(url):
		return "habr"
	case instagram.Match(url):
		return "instagram"
	case keybase.Match(url):
		return "keybase"
	case crates.Match(url):
		return "crates"
	case dockerhub.Match(url):
		return "dockerhub"
	case tiktok.Match(url):
		return "tiktok"
	case vkontakte.Match(url):
		return "vkontakte"
	case weibo.Match(url):
		return "weibo"
	case mastodon.Match(url):
		return "mastodon"
	case gravatar.Match(url):
		return "gravatar"
	case mailru.Match(url):
		return "mailru"
	case huggingface.Match(url):
		return "huggingface"
	case hackerone.Match(url):
		return "hackerone"
	case bugcrowd.Match(url):
		return "bugcrowd"
	case holopin.Match(url):
		return "holopin"
	case slideshare.Match(url):
		return "slideshare"
	default:
		return "website"
	}
}

// platformMatches checks if a URL matches the given platform name.
func platformMatches(url, platform string) bool {
	switch platform {
	case "github":
		return github.Match(url)
	case "gitlab":
		return gitlab.Match(url)
	case "codeberg":
		return codeberg.Match(url)
	case "google":
		return google.Match(url)
	case "linkedin":
		return linkedin.Match(url)
	case "twitter":
		return twitter.Match(url)
	case "reddit":
		return reddit.Match(url)
	case "youtube":
		return youtube.Match(url)
	case "stackoverflow":
		return stackoverflow.Match(url)
	case "bluesky":
		return bluesky.Match(url)
	case "mastodon":
		return mastodon.Match(url)
	case "medium":
		return medium.Match(url)
	case "microblog":
		return microblog.Match(url)
	case "instagram":
		return instagram.Match(url)
	case "tiktok":
		return tiktok.Match(url)
	case "vkontakte":
		return vkontakte.Match(url)
	case "weibo":
		return weibo.Match(url)
	case "gravatar":
		return gravatar.Match(url)
	case "mailru":
		return mailru.Match(url)
	case "keybase":
		return keybase.Match(url)
	case "crates":
		return crates.Match(url)
	case "dockerhub":
		return dockerhub.Match(url)
	case "huggingface":
		return huggingface.Match(url)
	case "hackerone":
		return hackerone.Match(url)
	case "bugcrowd":
		return bugcrowd.Match(url)
	case "holopin":
		return holopin.Match(url)
	case "slideshare":
		return slideshare.Match(url)
	default:
		return false
	}
}

// FetchRecursiveWithGuess is like FetchRecursive but also guesses related profiles
// based on discovered usernames. Guessed profiles are marked with IsGuess=true
// and include confidence scores.
func FetchRecursiveWithGuess(ctx context.Context, url string, opts ...Option) ([]*profile.Profile, error) {
	// First do normal recursive fetch
	profiles, err := FetchRecursive(ctx, url, opts...)
	if err != nil {
		return nil, err
	}

	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Build fetcher function that wraps our Fetch
	fetcher := func(ctx context.Context, url string) (*profile.Profile, error) {
		return Fetch(ctx, url, opts...)
	}

	// Guess additional profiles
	guessCfg := guess.Config{
		Logger:           cfg.logger,
		Fetcher:          fetcher,
		PlatformDetector: PlatformForURL,
	}

	guessed := guess.Related(ctx, profiles, guessCfg)

	// Append guessed profiles to result
	profiles = append(profiles, guessed...)

	return profiles, nil
}

// GuessFromUsername guesses profiles across platforms based on a username.
// It creates a synthetic profile with the username and searches for matching
// profiles on supported platforms. All returned profiles are marked with IsGuess=true
// and include confidence scores.
func GuessFromUsername(ctx context.Context, username string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// Create a synthetic profile with just the username
	seedProfile := &profile.Profile{
		Platform: "unknown",
		Username: username,
	}

	// Build fetcher function
	fetcher := func(ctx context.Context, url string) (*profile.Profile, error) {
		return Fetch(ctx, url, opts...)
	}

	// Guess profiles
	guessCfg := guess.Config{
		Logger:           cfg.logger,
		Fetcher:          fetcher,
		PlatformDetector: PlatformForURL,
	}

	guessed := guess.Related(ctx, []*profile.Profile{seedProfile}, guessCfg)

	return guessed, nil
}

// FetchEmailRecursive fetches profiles from email-based services and recursively
// follows social links. Multiple emails are treated as belonging to the same person,
// with results deduplicated by URL.
func FetchEmailRecursive(ctx context.Context, emails []string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	// First, get seed profiles from all emails
	seedProfiles, err := FetchEmail(ctx, emails, opts...)
	if err != nil {
		return nil, err
	}

	if len(seedProfiles) == 0 {
		return nil, nil
	}

	// Track visited URLs to avoid duplicates
	visited := make(map[string]bool)
	var allProfiles []*profile.Profile

	// Add seed profiles and mark as visited
	for _, p := range seedProfiles {
		normalizedURL := normalizeURL(p.URL)
		if !visited[normalizedURL] {
			visited[normalizedURL] = true
			allProfiles = append(allProfiles, p)
		}
	}

	// Collect all social links from seed profiles
	type queueItem struct {
		url   string
		depth int
	}
	const maxDepth = 3
	const maxLinksPerPage = 8

	var queue []queueItem
	for _, p := range seedProfiles {
		for _, link := range p.SocialLinks {
			if !visited[normalizeURL(link)] && isValidProfileURL(link) {
				queue = append(queue, queueItem{url: link, depth: 1})
			}
		}
		if p.Website != "" && !visited[normalizeURL(p.Website)] {
			queue = append(queue, queueItem{url: p.Website, depth: 1})
		}
	}

	// Process queue (same logic as FetchRecursive)
	for len(queue) > 0 {
		item := queue[0]
		queue = queue[1:]

		// Resolve redirects before fetching
		item.url = resolveURLRedirects(ctx, item.url, cfg.logger)

		normalizedURL := normalizeURL(item.url)
		if visited[normalizedURL] {
			continue
		}
		visited[normalizedURL] = true

		cfg.logger.InfoContext(ctx, "fetching profile", "url", item.url, "depth", item.depth, "visited", len(visited))

		p, err := Fetch(ctx, item.url, opts...)
		if err != nil {
			cfg.logger.WarnContext(ctx, "failed to fetch profile", "url", item.url, "error", err)
			continue
		}
		allProfiles = append(allProfiles, p)

		// Don't crawl further if we've hit max depth
		if item.depth >= maxDepth {
			continue
		}

		// From generic pages, only follow known social platform links
		onlyKnownPlatforms := p.Platform == "website"

		var linksToQueue []string
		for _, link := range p.SocialLinks {
			if !visited[normalizeURL(link)] && isValidProfileURL(link) {
				if !onlyKnownPlatforms || isSocialPlatform(link) || isSameDomainContactPage(link, item.url) {
					linksToQueue = append(linksToQueue, link)
				}
			}
		}

		if p.Website != "" && !visited[normalizeURL(p.Website)] {
			linksToQueue = append(linksToQueue, p.Website)
		}

		// Queue links from Fields map (sorted for deterministic iteration)
		keys := make([]string, 0, len(p.Fields))
		for k := range p.Fields {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := p.Fields[k]
			if isLikelySocialURL(k, v) && !visited[normalizeURL(v)] {
				linksToQueue = append(linksToQueue, v)
			}
		}

		if len(linksToQueue) > maxLinksPerPage {
			linksToQueue = linksToQueue[:maxLinksPerPage]
		}

		// Deduplicate links (redirects are resolved when URLs are fetched from queue)
		linksToQueue = dedupeLinks(linksToQueue, visited)

		for _, link := range linksToQueue {
			queue = append(queue, queueItem{url: link, depth: item.depth + 1})
		}
	}

	return allProfiles, nil
}

// FetchEmail fetches profiles from email-based services (Gravatar, Mail.ru, Google, GitHub).
// It returns all profiles found for the given email addresses.
func FetchEmail(ctx context.Context, emails []string, opts ...Option) ([]*profile.Profile, error) {
	cfg := &config{logger: slog.Default()}
	for _, opt := range opts {
		opt(cfg)
	}

	var profiles []*profile.Profile
	hasGitHub := false

	for _, email := range emails {
		// Always try Gravatar (works for any email)
		if p, err := fetchGravatar(ctx, email, cfg); err == nil && p != nil {
			profiles = append(profiles, p)
		}

		// Try Mail.ru for Mail.ru domain emails
		if mailru.Match(email) {
			if p, err := fetchMailRu(ctx, email, cfg); err == nil && p != nil {
				profiles = append(profiles, p)
			}
		}

		// Try Google for Gmail addresses
		if google.Match(email) {
			if p, err := fetchGoogle(ctx, email, cfg); err == nil && p != nil {
				profiles = append(profiles, p)
			}
		}

		// Try to find GitHub username from email (if we don't have a GitHub profile yet)
		if !hasGitHub {
			if p := fetchGitHubByEmail(ctx, email, cfg); p != nil {
				profiles = append(profiles, p)
				hasGitHub = true
			}
		}
	}

	return profiles, nil
}

// fetchGitHubByEmail looks up a GitHub profile by email address.
func fetchGitHubByEmail(ctx context.Context, email string, cfg *config) *profile.Profile {
	ghOpts := []github.Option{github.WithLogger(cfg.logger)}
	if cfg.cache != nil {
		ghOpts = append(ghOpts, github.WithHTTPCache(cfg.cache))
	}
	if cfg.githubToken != "" {
		ghOpts = append(ghOpts, github.WithToken(cfg.githubToken))
	}

	client, err := github.New(ctx, ghOpts...)
	if err != nil {
		cfg.logger.WarnContext(ctx, "failed to create GitHub client for email lookup", "error", err)
		return nil
	}

	username := client.UsernameFromEmail(ctx, email)
	if username == "" {
		return nil
	}

	// Fetch the full profile
	profileURL := fmt.Sprintf("https://github.com/%s", username)
	p, err := client.Fetch(ctx, profileURL)
	if err != nil {
		cfg.logger.WarnContext(ctx, "failed to fetch GitHub profile", "username", username, "error", err)
		return nil
	}

	// Add the email to the profile fields
	if p.Fields == nil {
		p.Fields = make(map[string]string)
	}
	p.Fields["lookup_email"] = email

	return p
}
