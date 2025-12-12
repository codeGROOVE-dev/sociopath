# sociopath

<img src="media/logo-small.png">

[![Go Reference](https://pkg.go.dev/badge/github.com/codeGROOVE-dev/sociopath.svg)](https://pkg.go.dev/github.com/codeGROOVE-dev/sociopath)
[![Go Report Card](https://goreportcard.com/badge/github.com/codeGROOVE-dev/sociopath)](https://goreportcard.com/report/github.com/codeGROOVE-dev/sociopath)

A Go library and CLI that fetches, spiders, and guesses social media profiles across 18+ platforms.

## Install

```bash
go install github.com/codeGROOVE-dev/sociopath/cmd/sociopath@latest
```

## Usage

```bash
sociopath https://github.com/torvalds              # Fetch single profile
sociopath -r https://linktr.ee/johndoe             # Follow all social links
sociopath --guess https://github.com/johndoe       # Discover profiles by username
```

### Recursive Mode (`-r`)
Follows social links found in profiles up to 3 levels deep.

### Guess Mode (`--guess`)
Probes other platforms using discovered usernames. Each guess includes a confidence
score based on username match, name similarity, location, bio keywords, and cross-links.

## Platforms

| No Auth Required | Auth Required (browser cookies) |
|------------------|--------------------------------|
| GitHub, Mastodon, BlueSky, Codeberg | LinkedIn, Twitter/X |
| Dev.to, StackOverflow, Linktree | Instagram, TikTok, VKontakte |
| Medium, Reddit, YouTube, Substack | |
| Bilibili, Habr, Generic websites | |

## Options

```
-r, --recursive   Follow social links recursively (max depth: 3)
--guess           Discover related profiles on other platforms
--browser         Enable browser cookie extraction for authenticated platforms
--no-cache        Disable HTTP caching (default: 75-day TTL)
-v, --debug       Enable verbose logging
```

## Output

JSON to stdout. Guessed profiles include confidence scores:

```json
{"Platform":"github","URL":"https://github.com/torvalds","Username":"torvalds","Name":"Linus Torvalds"}
{"IsGuess":true,"Confidence":0.85,"GuessMatch":["username:exact","name:github"]}
```

## Library

```go
import "github.com/codeGROOVE-dev/sociopath/pkg/sociopath"

profiles, _ := sociopath.FetchRecursiveWithGuess(ctx, url, sociopath.WithBrowserCookies())
for _, p := range profiles {
    fmt.Printf("%s (%.0f%% confidence)\n", p.URL, p.Confidence*100)
}
```
