package htmlutil

import "testing"

func TestExtractRedirectURL(t *testing.T) {
	tests := []struct {
		name    string
		html    string
		want    string
		wantNil bool
	}{
		{
			name: "meta refresh with url",
			html: `<html><head><meta http-equiv="refresh" content="0; url=http://choosehappy.dev/" /></head></html>`,
			want: "http://choosehappy.dev/",
		},
		{
			name: "meta refresh uppercase URL",
			html: `<html><head><meta http-equiv="refresh" content="5;URL=https://example.com" /></head></html>`,
			want: "https://example.com",
		},
		{
			name: "meta refresh with delay",
			html: `<html><head><meta http-equiv="refresh" content="10; url=https://redirect.example.com/page" /></head></html>`,
			want: "https://redirect.example.com/page",
		},
		{
			name: "window.location assignment",
			html: `<script>window.location = "https://newsite.com/";</script>`,
			want: "https://newsite.com/",
		},
		{
			name: "window.location.href assignment",
			html: `<script>window.location.href = "https://example.org/path";</script>`,
			want: "https://example.org/path",
		},
		{
			name: "location.href assignment",
			html: `<script>location.href = "https://redirected.com";</script>`,
			want: "https://redirected.com",
		},
		{
			name: "window.location.replace",
			html: `<script>window.location.replace("https://replaced.com/");</script>`,
			want: "https://replaced.com/",
		},
		{
			name: "document.location assignment",
			html: `<script>document.location = "https://doc-redirect.com";</script>`,
			want: "https://doc-redirect.com",
		},
		{
			name: "no redirect",
			html: `<html><head><title>Normal Page</title></head><body>Hello</body></html>`,
			want: "",
		},
		{
			name: "fragment only ignored",
			html: `<script>location.href = "#section";</script>`,
			want: "",
		},
		{
			name: "self-reference ignored",
			html: `<script>location.href = ".";</script>`,
			want: "",
		},
		{
			name: "meta refresh takes precedence over JS",
			html: `<html><head><meta http-equiv="refresh" content="0; url=https://meta.com" /></head><script>window.location = "https://js.com";</script></html>`,
			want: "https://meta.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractRedirectURL(tt.html)
			if got != tt.want {
				t.Errorf("ExtractRedirectURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
