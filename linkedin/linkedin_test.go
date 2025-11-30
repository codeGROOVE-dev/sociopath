package linkedin

import "testing"

func TestMatch(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://www.linkedin.com/in/johndoe", true},
		{"https://linkedin.com/in/johndoe", true},
		{"https://linkedin.com/in/johndoe/", true},
		{"linkedin.com/in/johndoe", true},
		{"https://LINKEDIN.COM/IN/johndoe", true},
		{"https://linkedin.com/company/acme", false},
		{"https://twitter.com/johndoe", false},
		{"https://example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := Match(tt.url)
			if got != tt.want {
				t.Errorf("Match(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}

func TestAuthRequired(t *testing.T) {
	if !AuthRequired() {
		t.Error("LinkedIn should require auth")
	}
}

func TestExtractPublicID(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://linkedin.com/in/johndoe", "johndoe"},
		{"https://linkedin.com/in/johndoe/", "johndoe"},
		{"https://linkedin.com/in/john-doe-123", "john-doe-123"},
		{"https://example.com", ""},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			got := extractPublicID(tt.url)
			if got != tt.want {
				t.Errorf("extractPublicID(%q) = %q, want %q", tt.url, got, tt.want)
			}
		})
	}
}

func TestParseCompanyFromHeadline(t *testing.T) {
	tests := []struct {
		headline string
		want     string
	}{
		{"Software Engineer at Google", "Google"},
		{"CEO @ Startup", "Startup"},
		{"Engineer, Acme Corp", "Acme Corp"},
		{"Senior Developer at Meta, Inc.", "Meta"},
		{"Just a person", ""},
	}

	for _, tt := range tests {
		t.Run(tt.headline, func(t *testing.T) {
			got := parseCompanyFromHeadline(tt.headline)
			if got != tt.want {
				t.Errorf("parseCompanyFromHeadline(%q) = %q, want %q", tt.headline, got, tt.want)
			}
		})
	}
}

func TestExtractJSONField(t *testing.T) {
	json := `{"firstName":"John","lastName":"Doe","headline":"Engineer"}`

	tests := []struct {
		field string
		want  string
	}{
		{"firstName", "John"},
		{"lastName", "Doe"},
		{"headline", "Engineer"},
		{"missing", ""},
	}

	for _, tt := range tests {
		t.Run(tt.field, func(t *testing.T) {
			got := extractJSONField(json, tt.field)
			if got != tt.want {
				t.Errorf("extractJSONField(%q) = %q, want %q", tt.field, got, tt.want)
			}
		})
	}
}

func TestUnescapeJSON(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{`hello\nworld`, "hello\nworld"},
		{`Tom \u0026 Jerry`, "Tom & Jerry"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := unescapeJSON(tt.input)
			if got != tt.want {
				t.Errorf("unescapeJSON(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
