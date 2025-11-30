# sociopath

A Go tool for fetching social media profiles across 20+ platforms.

## Installation

```bash
go install github.com/codeGROOVE-dev/sociopath/cmd/sociopath@latest
```

## Usage

```bash
sociopath https://github.com/torvalds              # Single profile
sociopath -r https://linktr.ee/johndoe             # Follow all social links
sociopath --guess https://github.com/johndoe       # Find profiles by username
```

## The Power Features

### Recursive Mode (`-r`)

Follows social links found in profiles up to 3 levels deep. Start with a Linktree
or personal website and discover all connected profiles:

```bash
$ sociopath -r https://linktr.ee/example
# Returns: Linktree -> Twitter -> GitHub -> Mastodon -> ...
```

### Guess Mode (`--guess`)

The real magic. Probes other platforms using discovered usernames. Each guess
includes a confidence score based on username match, name similarity, location
overlap, bio keywords, and cross-links between profiles:

```bash
$ sociopath --guess https://github.com/johndoe
# Finds johndoe on Twitter, Mastodon, BlueSky, Dev.to, etc.
# Each guessed profile: "IsGuess": true, "Confidence": 0.85
```

## Supported Platforms

| No Auth Required | Auth Required (browser cookies) |
|------------------|--------------------------------|
| GitHub, Mastodon, BlueSky | LinkedIn, Twitter/X |
| Dev.to, StackOverflow, Linktree | Instagram, TikTok |
| Medium, Reddit, YouTube | VKontakte, Weibo |
| Substack, Zhihu, Bilibili, Habr | |
| Generic websites | |

## Options

```
-r            Recursively fetch profiles from discovered links
--guess       Guess related profiles on other platforms (implies -r)
--no-browser  Disable automatic browser cookie extraction
--no-cache    Disable HTTP caching (default: 75-day TTL)
-v, -debug    Enable verbose logging
```

## Output

JSON to stdout. Single profile for basic fetch, array for `-r`/`--guess`:

```json
{
  "Platform": "github",
  "URL": "https://github.com/torvalds",
  "Username": "torvalds",
  "Name": "Linus Torvalds",
  "Location": "Portland, OR",
  "SocialLinks": ["https://twitter.com/..."]
}
```

Guessed profiles include:

```json
{ "IsGuess": true, "Confidence": 0.85, "GuessMatch": ["username:exact", "name:github"] }
```

## Library Usage

```go
profiles, _ := sociopath.FetchRecursiveWithGuess(ctx, url,
    sociopath.WithBrowserCookies(),
    sociopath.WithLogger(logger))

for _, p := range profiles {
    if p.IsGuess {
        fmt.Printf("%s (%.0f%% confidence)\n", p.URL, p.Confidence*100)
    }
}
```
