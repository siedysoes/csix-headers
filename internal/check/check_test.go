package check

import (
	"net/http"
	"net/url"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func findCheck(rep Report, name string) *Check {
	for i := range rep.Checks {
		if rep.Checks[i].Name == name {
			return &rep.Checks[i]
		}
	}
	return nil
}

func TestEvaluateFullHeaders(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
	h.Set("Permissions-Policy", "camera=(), microphone=()")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
	h.Set("Cross-Origin-Embedder-Policy", "require-corp")
	h.Set("Cross-Origin-Resource-Policy", "same-origin")

	rep := Evaluate(mustURL(t, "https://example.com"), h)
	if rep.Score != rep.Max || rep.Grade != "A+" {
		t.Errorf("full headers: score=%d/%d grade=%s, diharapkan A+ penuh", rep.Score, rep.Max, rep.Grade)
	}
}

func TestEvaluateEmptyHeaders(t *testing.T) {
	rep := Evaluate(mustURL(t, "https://example.com"), http.Header{})
	// Referrer-Policy default browser (5) + Permissions-Policy (4) = 9
	if rep.Score != 9 {
		t.Errorf("empty headers: score = %d, diharapkan 9", rep.Score)
	}
	if rep.Grade != "F" {
		t.Errorf("empty headers: grade = %s, diharapkan F", rep.Grade)
	}
}

func TestEvaluateHTTPTargetExcludesHSTS(t *testing.T) {
	rep := Evaluate(mustURL(t, "http://example.com"), http.Header{})
	if rep.Max != 80 {
		t.Errorf("target HTTP: max = %d, diharapkan 80 (HSTS dikecualikan)", rep.Max)
	}
	c := findCheck(rep, "Strict-Transport-Security (HSTS)")
	if c == nil || c.Status != StatusInfo {
		t.Errorf("target HTTP: HSTS seharusnya berstatus info")
	}
}

func TestHSTSShortMaxAge(t *testing.T) {
	h := http.Header{}
	h.Set("Strict-Transport-Security", "max-age=1000")
	rep := Evaluate(mustURL(t, "https://example.com"), h)
	c := findCheck(rep, "Strict-Transport-Security (HSTS)")
	if c == nil || c.Status != StatusPartial || c.Weight != 6 {
		t.Errorf("max-age pendek: %+v, diharapkan partial 6", c)
	}
}

func TestCSPUnsafeInline(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "script-src 'unsafe-inline'")
	rep := Evaluate(mustURL(t, "https://example.com"), h)
	c := findCheck(rep, "Content-Security-Policy (CSP)")
	if c == nil || c.Status != StatusPartial || c.Weight != 8 {
		t.Errorf("unsafe-inline: %+v, diharapkan partial 8", c)
	}
}

func TestXFOViaFrameAncestors(t *testing.T) {
	h := http.Header{}
	h.Set("Content-Security-Policy", "frame-ancestors 'none'")
	rep := Evaluate(mustURL(t, "https://example.com"), h)
	c := findCheck(rep, "X-Frame-Options / frame-ancestors")
	if c == nil || c.Status != StatusPass || c.Weight != 10 {
		t.Errorf("frame-ancestors: %+v, diharapkan pass 10 (tanpa XFO)", c)
	}
}

func TestGradeBoundaries(t *testing.T) {
	cases := map[float64]string{
		100: "A+", 90: "A", 80: "A-", 65: "B", 50: "C", 35: "D", 34.9: "F", 0: "F",
	}
	for pct, want := range cases {
		if got := grade(pct); got != want {
			t.Errorf("grade(%.1f) = %s, diharapkan %s", pct, got, want)
		}
	}
}

func TestNotesVersionDisclosure(t *testing.T) {
	h := http.Header{}
	h.Set("Server", "nginx/1.18.0")
	h.Set("X-Powered-By", "Express")
	rep := Evaluate(mustURL(t, "https://example.com"), h)
	if len(rep.Notes) != 2 {
		t.Errorf("notes = %v, diharapkan 2 catatan", rep.Notes)
	}
}
