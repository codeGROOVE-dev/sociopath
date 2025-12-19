# sociopath

<img src="media/logo-small.png">

[![Go Reference](https://pkg.go.dev/badge/github.com/codeGROOVE-dev/sociopath.svg)](https://pkg.go.dev/github.com/codeGROOVE-dev/sociopath)
[![Go Report Card](https://goreportcard.com/badge/github.com/codeGROOVE-dev/sociopath)](https://goreportcard.com/report/github.com/codeGROOVE-dev/sociopath)

Go library and CLI for fetching social media profiles across 200+ platforms.

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

**Code Hosting:** GitHub, GitLab, Codeberg, Sourcehut, Gitea, Gitee, GitVerse, NotABug, SourceForge, Launchpad, CodingNet

**Developer Communities:** StackOverflow, HackerNews, Lobsters, Slashdot, Dev.to, Hashnode, Qiita, Zenn, Velog, CSDN, Juejin, V2EX, CNBlogs, CNode, SegmentFault, Jianshu, OSChina, ITHelp, InfoQ CN, Zhihu, QnA Habr, VC.ru, Pikabu, Developpez, LinuxFR, Zeste de Savoir, DesarrolloWeb, LaWebDelProgramador, Cristalab, ForosDelWeb, TabNews, GUJ, VivaOLinux, iMasters, Nairaland, KotaKode, Codepolitan, Dicoding, PetaniKode, Kaskus, OKKY, Programmers, DOU, Wykop, 4Programmers, OhjelmoIntiputka, SweClockers, Hugi, Barnamenevis, Virgool, Quera, Eksisozluk, SQL.ru, RSDN, RubyChina, TechBBS, Daily.dev, Peerlist, HackerNoon, GeeksForGeeks, Hackaday, Hackster, DevRant

**Forums & Communities:** Discourse, ArchBBS, LinuxQuestions, Linux.org, LinuxMint Forums, Gentoo Forums, Unix.com, Swift Forums, Ionic Forum, Kubernetes Discuss, CNCF Community, HashiCorp Discuss, Grafana Community, MS Tech Community, F-Droid Forum, XDA Forums, Flashback

**Package Registries:** Crates.io, DockerHub, Quay, HexPM, npm, PyPI, RubyGems, NuGet, Packagist

**Competitive Programming:** LeetCode, LeetCode CN, Exercism, CodeWars, AtCoder, Codeforces, CodeChef, TopCoder, HackerRank, HackerEarth, SPOJ, Monkeytype, CodinGame

**Code Playgrounds:** Kaggle, CodePen, CodeSandbox, StackBlitz, JSFiddle, FreeCodeCamp, Replit, Scratch, ObservableHQ, Asciinema

**Security & CTF:** HackerOne, Bugcrowd, Intigriti, YesWeHack, TryHackMe, HackThisSite, HackenProof, Detectify, Immunefi, OpenBugBounty, PortSwigger Academy, CyberDefenders, pwn.college, picoCTF, CryptoHack, Crackmes.one, RingZer0, W3Challs, CTF247, 0x00sec, HTB Academy

**Professional:** ORCID, HuggingFace, Keybase, Sessionize, SlideShare, Cloudflare, StackShare, Figma, WakaTime, TradingView, CakeResume, AngelList, Notist, AWS Builder, Google Cloud, Pulumi, OpenHub

**Design & Creative:** Behance, Awwwards, CSS Design Awards, Frontend Mentor, Dribbble

**Social:** Twitter/X*, LinkedIn*, Instagram*, TikTok*, Mastodon, BlueSky, Reddit, VKontakte, Weibo, Micro.blog, Telegram, Discord*, Skype, Tumblr

**Content & Blogs:** YouTube, Twitch, Bilibili, Medium, Substack, Habr, Blogger, Pastebin, Tistory, Naver Blog

**Gaming & Leisure:** Steam, Strava, Goodreads, Douban, Duolingo, BoardGameGeek, itch.io, Lichess, Backloggd, Nexus Mods

**Other:** Linktree, Gravatar, Google, GoogleCal, Cal.com, Calendly, Holopin, IntenseDebate, Disqus, ArsTechnica, Mail.ru, Hahow, TipidPC, CTO51

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
