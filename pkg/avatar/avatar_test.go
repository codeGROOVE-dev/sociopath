package avatar

import "testing"

func TestDistance(t *testing.T) {
	tests := []struct {
		name string
		a, b uint64
		want int
	}{
		{"identical", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 0},
		{"one bit different", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 1},
		{"all different", 0x0, 0xFFFFFFFFFFFFFFFF, 64},
		{"half different", 0xFFFFFFFF00000000, 0x00000000FFFFFFFF, 64},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Distance(tt.a, tt.b); got != tt.want {
				t.Errorf("Distance() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSimilar(t *testing.T) {
	tests := []struct {
		name string
		a, b uint64
		want bool
	}{
		{"identical", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, true},
		{"close", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFF0, true},     // 4 bits different
		{"far", 0xFFFFFFFFFFFFFFFF, 0x0, false},                     // 64 bits different
		{"zero a", 0, 0xFFFFFFFFFFFFFFFF, false},                    // zero means unknown
		{"zero b", 0xFFFFFFFFFFFFFFFF, 0, false},                    // zero means unknown
		{"threshold", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFC00, true}, // exactly 10 bits different
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Similar(tt.a, tt.b); got != tt.want {
				t.Errorf("Similar() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestScore(t *testing.T) {
	tests := []struct {
		name    string
		a, b    uint64
		wantMin float64
		wantMax float64
	}{
		{"identical", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF, 1.0, 1.0},
		{"zero a", 0, 0xFFFFFFFFFFFFFFFF, 0, 0},
		{"zero b", 0xFFFFFFFFFFFFFFFF, 0, 0, 0},
		{"close", 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFE, 0.8, 1.0}, // 1 bit = 0.9
		{"far", 0xFFFFFFFFFFFFFFFF, 0x0, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Score(tt.a, tt.b)
			if got < tt.wantMin || got > tt.wantMax {
				t.Errorf("Score() = %v, want between %v and %v", got, tt.wantMin, tt.wantMax)
			}
		})
	}
}

func TestIsDefaultAvatar(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://gravatar.com/avatar/abc?d=identicon", true},
		{"https://example.com/identicon/abc.png", true},
		{"https://github.com/avatar_default_image.png", true},
		{"https://example.com/user/photo.jpg", false},
		{"https://pbs.twimg.com/profile_images/123.jpg", false},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := isDefaultAvatar(tt.url); got != tt.want {
				t.Errorf("isDefaultAvatar(%q) = %v, want %v", tt.url, got, tt.want)
			}
		})
	}
}
