package discovery

import (
	"net/url"
	"strings"
)

// knownSocialDomains contains domains of established social platforms and
// well-known projects where identity discovery would be pointless.
var knownSocialDomains = map[string]bool{
	// Code hosting
	"github.com": true, "github.blog": true, "gitlab.com": true, "bitbucket.org": true,
	"codeberg.org": true, "gitee.com": true, "sr.ht": true, "sourceforge.net": true,
	// Social media
	"twitter.com": true, "x.com": true, "facebook.com": true, "instagram.com": true,
	"linkedin.com": true, "tiktok.com": true, "youtube.com": true, "twitch.tv": true,
	"reddit.com": true, "discord.com": true, "slack.com": true, "telegram.org": true,
	"t.me": true, "whatsapp.com": true, "signal.org": true,
	"angel.co": true, "wellfound.com": true, "noti.st": true,
	// Blogging / Content
	"medium.com": true, "substack.com": true, "dev.to": true, "hashnode.dev": true,
	"wordpress.com": true, "blogger.com": true, "ghost.org": true,
	// Frontend development platforms
	"frontendmentor.io": true, "daily.dev": true, "app.daily.dev": true,
	"peerlist.io": true, "codesandbox.io": true, "stackblitz.com": true,
	"awwwards.com": true, "cssdesignawards.com": true,
	// Q&A / Forums
	"stackoverflow.com": true, "stackexchange.com": true,
	"quora.com": true, "news.ycombinator.com": true,
	// Mobile development forums
	"xdaforums.com": true, "forum.f-droid.org": true,
	"forum.ionicframework.com": true, "forums.swift.org": true,
	// Linux forums
	"linuxquestions.org": true, "phoronix.com": true, "forums.phoronix.com": true,
	"bbs.archlinux.org": true, "unix.com": true, "openhub.net": true,
	"forums.linuxmint.com": true, "forums.gentoo.org": true,
	// Discourse-based Linux forums
	"discourse.nixos.org": true, "discuss.kde.org": true,
	"community.pop-os.org": true, "forum.endeavouros.com": true,
	"discourse.ubuntu.com": true, "forums.opensuse.org": true,
	// Identity / Social
	"keybase.io": true, "bsky.app": true, "mastodon.social": true,
	"hachyderm.io": true, "fosstodon.org": true, "infosec.exchange": true,
	"gravatar.com": true,
	// Package registries
	"npmjs.com": true, "pypi.org": true, "rubygems.org": true, "crates.io": true,
	"hex.pm": true, "packagist.org": true, "nuget.org": true,
	"hub.docker.com": true, "docker.io": true, "docker.com": true, "quay.io": true,
	"huggingface.co": true, "app.pulumi.com": true,
	// Regional social
	"vk.com": true, "ok.ru": true, "weibo.com": true, "bilibili.com": true,
	// Chinese developer communities
	"csdn.net": true, "segmentfault.com": true, "jianshu.com": true,
	"cnodejs.org": true, "ruby-china.org": true, "oschina.net": true,
	"cnblogs.com": true, "zhihu.com": true, "leetcode.cn": true,
	"infoq.cn": true, "51cto.com": true, "coding.net": true,
	"juejin.cn": true, "v2ex.com": true, "douban.com": true,
	// Taiwanese developer communities
	"ithelp.ithome.com.tw": true, "ithome.com.tw": true,
	"cakeresume.com": true, "cake.me": true, "hahow.in": true,
	// Filipino developer communities
	"tipidpc.com": true,
	// Korean developer communities
	"tistory.com": true, "programmers.co.kr": true, "okky.kr": true,
	"naver.com": true,
	// Nordic developer communities
	"ohjelmointiputka.net": true, "bbs.io-tech.fi": true, "io-tech.fi": true,
	"sweclockers.com": true, "flashback.org": true, "hugi.is": true,
	// Iranian developer communities
	"virgool.io": true, "quera.org": true, "barnamenevis.org": true,
	// Turkish developer communities
	"eksisozluk.com": true,
	// Polish developer communities
	"4programmers.net": true, "wykop.pl": true,
	// Spanish/Latin American developer communities
	"forosdelweb.com": true, "lawebdelprogramador.com": true, "cristalab.com": true,
	"desarrolloweb.com": true,
	"maestrosdelweb.com": true,
	// Media sharing
	"pinterest.com": true, "tumblr.com": true, "flickr.com": true,
	"soundcloud.com": true, "spotify.com": true, "bandcamp.com": true,
	"dribbble.com": true, "behance.net": true,
	// Funding / Support
	"patreon.com": true, "ko-fi.com": true, "buymeacoffee.com": true,
	"opencollective.com": true, "gofundme.com": true,
	// Link aggregators
	"linktree.com": true, "linktr.ee": true, "bio.link": true,
	// Coding challenges
	"leetcode.com": true, "codewars.com": true, "hackerrank.com": true,
	"exercism.org": true, "freecodecamp.org": true, "codepen.io": true,
	"geeksforgeeks.org": true,
	// Competitive programming platforms
	"codechef.com": true, "codeforces.com": true, "atcoder.jp": true,
	"spoj.com": true, "topcoder.com": true,
	// Security platforms
	"hackerone.com": true, "bugcrowd.com": true, "tryhackme.com": true,
	"immunefi.com": true, "openbugbounty.org": true, "detectify.com": true,
	"hackenproof.com": true, "picoctf.org": true, "play.picoctf.org": true,
	"crackmes.one": true, "0x00sec.org": true,
	// CTF platforms
	"247ctf.com": true, "w3challs.com": true, "cryptohack.org": true,
	"cyberdefenders.org": true, "ringzer0ctf.com": true, "hackthissite.org": true,
	"portswigger.net": true, "hackthebox.com": true, "academy.hackthebox.com": true,
	"pwn.college": true,
	// Gaming / Modding
	"steam.com": true, "steamcommunity.com": true, "steampowered.com": true,
	"nexusmods.com": true,
	// Programming languages (official sites - not personal domains)
	"python.org": true, "golang.org": true, "go.dev": true, "rust-lang.org": true,
	"ruby-lang.org": true, "nodejs.org": true, "deno.land": true, "typescriptlang.org": true,
	"kotlinlang.org": true, "swift.org": true, "scala-lang.org": true, "elixir-lang.org": true,
	"haskell.org": true, "clojure.org": true, "erlang.org": true, "julialang.org": true,
	"r-project.org": true, "perl.org": true, "php.net": true, "lua.org": true,
	"java.com": true, "oracle.com": true, "dotnet.microsoft.com": true,
	// Frameworks and libraries
	"reactjs.org": true, "react.dev": true, "vuejs.org": true, "angular.io": true,
	"svelte.dev": true, "nextjs.org": true, "nuxt.com": true, "astro.build": true,
	"remix.run": true, "gatsby.dev": true, "ember.com": true,
	"djangoproject.com": true, "rubyonrails.org": true, "laravel.com": true,
	"spring.io": true, "symfony.com": true, "flask.palletsprojects.com": true,
	"expressjs.com": true, "fastapi.tiangolo.com": true,
	// Infrastructure / DevOps
	"kubernetes.io": true, "terraform.io": true, "ansible.com": true,
	"nginx.org": true, "nginx.com": true,
	"aws.amazon.com": true, "cloud.google.com": true, "azure.microsoft.com": true,
	"digitalocean.com": true, "heroku.com": true, "railway.app": true, "render.com": true,
	"discuss.hashicorp.com": true, "community.grafana.com": true,
	// Operating systems / Foundations
	"linux.org": true, "kernel.org": true, "debian.org": true, "ubuntu.com": true,
	"fedoraproject.org": true, "archlinux.org": true, "freebsd.org": true,
	"mozilla.org": true, "chromium.org": true, "webkit.org": true,
	"apache.org": true, "eclipse.org": true, "cncf.io": true, "linuxfoundation.org": true,
	// Educational platforms
	"scratch.mit.edu": true, "khanacademy.org": true, "coursera.org": true,
	"udemy.com": true, "edx.org": true, "codecademy.com": true,
	// Search / Big tech
	"google.com": true, "microsoft.com": true, "apple.com": true, "amazon.com": true,
	"meta.com": true, "netflix.com": true,
}

// hostingSuffixes contains common hosting platform suffixes.
var hostingSuffixes = []string{
	".github.io", ".gitlab.io", ".netlify.app", ".vercel.app", ".pages.dev",
}

// IsKnownSocialDomain returns true if the domain belongs to a known social platform.
func IsKnownSocialDomain(domain string) bool {
	domain = strings.ToLower(domain)

	if knownSocialDomains[domain] {
		return true
	}

	// Check if it's a subdomain of a known platform
	for known := range knownSocialDomains {
		if strings.HasSuffix(domain, "."+known) {
			return true
		}
	}

	// Check common hosting subdomains
	for _, suffix := range hostingSuffixes {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}

	return false
}

// ExtractDomain extracts the domain from a URL, stripping www. prefix and lowercasing.
func ExtractDomain(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		urlStr = "https://" + urlStr
	}

	parsed, err := url.Parse(urlStr)
	if err != nil {
		return ""
	}

	host := strings.ToLower(parsed.Hostname())
	host = strings.TrimPrefix(host, "www.")
	return host
}
