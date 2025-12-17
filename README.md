# sociopath

<img src="media/logo-small.png">

[![Go Reference](https://pkg.go.dev/badge/github.com/codeGROOVE-dev/sociopath.svg)](https://pkg.go.dev/github.com/codeGROOVE-dev/sociopath)
[![Go Report Card](https://goreportcard.com/badge/github.com/codeGROOVE-dev/sociopath)](https://goreportcard.com/report/github.com/codeGROOVE-dev/sociopath)

Go library and CLI for fetching social media profiles across 100+ platforms.

## Install

```bash
go install github.com/codeGROOVE-dev/sociopath/cmd/sociopath@latest
```

## Usage

```bash
sociopath https://github.com/torvalds         # Fetch profile
sociopath -r https://linktr.ee/johndoe        # Follow social links recursively
sociopath --guess torvalds                    # Discover profiles by username
sociopath --email user@example.com            # Look up by email (Gravatar, etc.)
```

## Options

| Flag | Description |
|------|-------------|
| `-r` | Follow social links recursively (max depth: 3) |
| `--guess` | Discover related profiles on other platforms |
| `--email` | Look up profiles by email address |
| `--browser` | Extract cookies from browser for authenticated platforms |
| `--no-cache` | Disable HTTP caching (default: 75-day TTL) |
| `-v, --debug` | Enable verbose logging |

## Platforms

**Code Hosting:** GitHub, GitLab, Codeberg, Sourcehut, Gitea, Gitee, NotABug, SourceForge, Launchpad

**Developer Communities:** StackOverflow, HackerNews, Lobsters, Slashdot, Dev.to, Hashnode, Qiita, Zenn, Velog, CSDN, Juejin, V2EX, HackerNoon, GeeksForGeeks, Hackaday, Hackster, DevRant

**Package Registries:** Crates.io, DockerHub, HexPM, npm, PyPI, RubyGems

**Competitive Programming:** LeetCode, Exercism, CodeWars, AtCoder, Codeforces, CodeChef, TopCoder, HackerRank, HackerEarth, SPOJ, Monkeytype

**Code Playgrounds:** Kaggle, CodePen, JSFiddle, FreeCodeCamp, Replit, Scratch, ObservableHQ, Asciinema

**Security:** HackerOne, Bugcrowd, Intigriti, YesWeHack, TryHackMe

**Professional:** ORCID, HuggingFace, Keybase, Sessionize, SlideShare, Cloudflare, StackShare, Figma, WakaTime, TradingView

**Social:** Twitter/X*, LinkedIn*, Instagram*, TikTok*, Mastodon, BlueSky, Reddit, VKontakte, Weibo, Micro.blog, Telegram, Discord*, Skype, Tumblr

**Content:** YouTube, Twitch, Bilibili, Medium, Substack, Habr, Blogger, Pastebin

**Leisure:** Steam, Strava, Goodreads, Douban, Dribbble, Duolingo, BoardGameGeek

**Other:** Linktree, Gravatar, Google, GoogleCal, Cal.com, Calendly, Holopin, IntenseDebate, Disqus, ArsTechnica, Mail.ru

*\* Requires `--browser` flag for authentication*

## Output

JSON to stdout:

```json
{
  "Platform": "github",
  "URL": "https://github.com/torvalds",
  "Username": "torvalds",
  "Name": "Linus Torvalds"
}
```

Guessed profiles include confidence scores and match reasons.

## Library

```go
import "github.com/codeGROOVE-dev/sociopath/pkg/sociopath"

profiles, _ := sociopath.FetchRecursiveWithGuess(ctx, url, sociopath.WithBrowserCookies())
for _, p := range profiles {
    fmt.Printf("%s (%.0f%% confidence)\n", p.URL, p.Confidence*100)
}
```
