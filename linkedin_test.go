package linkedin

import (
	"testing"
)

func TestExtractField(t *testing.T) {
	tests := []struct {
		name  string
		html  string
		start string
		end   string
		want  string
	}{
		{
			name:  "basic extraction",
			html:  `{"firstName":"Thomas","lastName":"Stromberg"}`,
			start: `"firstName":"`,
			end:   `"`,
			want:  "Thomas",
		},
		{
			name:  "not found",
			html:  `{"firstName":"Thomas"}`,
			start: `"middleName":"`,
			end:   `"`,
			want:  "",
		},
		{
			name:  "empty value",
			html:  `{"firstName":""}`,
			start: `"firstName":"`,
			end:   `"`,
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractField(tt.html, tt.start, tt.end)
			if got != tt.want {
				t.Errorf("extractField() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnescapeJSON(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "unicode escape",
			in:   `Thomas Str\u00f6mberg`,
			want: "Thomas Strömberg",
		},
		{
			name: "no escape",
			in:   "Thomas Stromberg",
			want: "Thomas Stromberg",
		},
		{
			name: "quote escape",
			in:   `Hello \"World\"`,
			want: `Hello "World"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := unescapeJSON(tt.in)
			if got != tt.want {
				t.Errorf("unescapeJSON() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractMetaContent(t *testing.T) {
	tests := []struct {
		name     string
		html     string
		property string
		want     string
	}{
		{
			name:     "og:title",
			html:     `<meta property="og:title" content="Thomas Stromberg" />`,
			property: `property="og:title"`,
			want:     "Thomas Stromberg",
		},
		{
			name:     "og:description",
			html:     `<meta property="og:description" content="Software Engineer at Google" />`,
			property: `property="og:description"`,
			want:     "Software Engineer at Google",
		},
		{
			name:     "not found",
			html:     `<meta property="og:title" content="Test" />`,
			property: `property="og:image"`,
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMetaContent(tt.html, tt.property)
			if got != tt.want {
				t.Errorf("extractMetaContent() = %v, want %v", got, tt.want)
			}
		})
	}
}
