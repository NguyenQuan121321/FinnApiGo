package device

import "testing"

func TestParse(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want string
	}{
		{"empty", "", "Unknown device"},
		{"chrome windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36", "Chrome on Windows"},
		{"edge windows", "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Edg/120.0", "Edge on Windows"},
		{"firefox linux", "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0", "Firefox on Linux"},
		{"safari mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15) AppleWebKit/605.1.15 Safari/605.1.15", "Safari on macOS"},
		{"safari iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15", "Safari on iPhone"},
		{"chrome android", "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0 Mobile Safari/537.36", "Chrome on Android"},
		{"opera", "Mozilla/5.0 (Windows NT 10.0) OPR/110.0", "Opera on Windows"},
		{"chrome ios", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0) CriOS/120.0 Mobile Safari/605.1", "Chrome on iPhone"},
		{"bare mozilla only", "Mozilla/5.0", "Unknown device"},
		{"ipad", "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 Safari/605.1.15", "Safari on iPad"},
		{"browser only", "Firefox/120.0", "Firefox"},
		{"os only", "Mozilla/5.0 (applewebkit/linux)", "Linux"},
		{"opera legacy", "Opera/9.80", "Opera"},
		{"custom tool lowercase", "curl/7.88", "Curl"},
		{"custom tool uppercase", "PostmanRuntime/7.32", "PostmanRuntime"},
		{"preamble then custom", "Mozilla/5.0 AppleWebKit/537.36 CustomClient/1.0", "CustomClient"},
		{"only ignored symbols", "Mozilla/5.0 ( ) ; .", "Unknown device"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Parse(tc.ua); got != tc.want {
				t.Errorf("Parse(%q) = %q, want %q", tc.ua, got, tc.want)
			}
		})
	}
}

// TestParse_TruncatesOversized exercises the input-size guard so a pathological
// (huge) User-Agent cannot drive unbounded parsing work.
func TestParse_TruncatesOversized(t *testing.T) {
	huge := "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0 " + makeGarbage(MaxUserAgentLen*3)
	got := Parse(huge)
	// Still resolves a recognizable label despite truncation.
	if got != "Chrome on Windows" {
		t.Errorf("Parse(oversized) = %q, want %q", got, "Chrome on Windows")
	}
}

func makeGarbage(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'x'
	}
	return string(b)
}
