// Package check mengimplementasikan penilaian header keamanan HTTP
// (mirip securityheaders.com, tapi bisa jalan offline/lokal).
package check

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Version adalah versi tool.
const Version = "0.1.0"

// Status hasil sebuah pemeriksaan.
type Status string

const (
	StatusPass    Status = "pass"
	StatusPartial Status = "partial"
	StatusFail    Status = "fail"
	StatusInfo    Status = "info"
)

// Check adalah satu pemeriksaan header.
type Check struct {
	Name   string `json:"name"`
	Status Status `json:"status"`
	Weight int    `json:"weight"`
	Max    int    `json:"max"`
	Value  string `json:"value,omitempty"`
	Advice string `json:"advice,omitempty"`
}

// Report adalah hasil penilaian lengkap.
type Report struct {
	URL    string   `json:"url"`
	Score  int      `json:"score"`
	Max    int      `json:"max"`
	Grade  string   `json:"grade"`
	Checks []Check  `json:"checks"`
	Notes  []string `json:"notes"`
}

var (
	versionedRE = regexp.MustCompile(`\d+\.\d+`)
	maxAgeRE    = regexp.MustCompile(`max-age=(\d+)`)
)

// Fetch mengambil URL (mengikuti redirect) dan mengembalikan URL final + header.
func Fetch(rawURL string, timeout time.Duration, insecure bool) (*url.URL, http.Header, error) {
	client := &http.Client{Timeout: timeout}
	if insecure {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, nil, err
	}
	req.Header.Set("User-Agent", "csix-headers/"+Version+" (+https://github.com/siedysoes/csix-headers)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.Request.URL, resp.Header, nil
}

// Evaluate menilai seluruh header keamanan dari sebuah respons.
func Evaluate(target *url.URL, h http.Header) Report {
	isHTTPS := target.Scheme == "https"
	rep := Report{URL: target.String(), Checks: []Check{}, Notes: []string{}}
	max := 0

	add := func(c Check) {
		rep.Checks = append(rep.Checks, c)
		if c.Status != StatusInfo {
			max += c.Max
		}
	}

	dirs := cspDirectives(h)
	add(hstsCheck(h, isHTTPS))
	add(cspCheck(h, dirs))
	add(xctoCheck(h))
	add(xfoCheck(h, dirs))
	add(referrerCheck(h))
	add(permissionsCheck(h))
	add(coopCheck(h))
	add(coepCheck(h))
	add(corpCheck(h))

	if s := h.Get("Server"); s != "" && versionedRE.MatchString(s) {
		rep.Notes = append(rep.Notes, "Server: "+s+" — sembunyikan identitas & versi server")
	}
	if s := h.Get("X-Powered-By"); s != "" {
		rep.Notes = append(rep.Notes, "X-Powered-By: "+s+" — hapus header ini")
	}
	if s := h.Get("X-XSS-Protection"); s != "" {
		rep.Notes = append(rep.Notes, "X-XSS-Protection: "+s+" — header deprecated, hapus atau set 0")
	}
	if s := h.Get("X-AspNet-Version"); s != "" {
		rep.Notes = append(rep.Notes, "X-AspNet-Version: "+s+" — hapus header ini")
	}

	rep.Max = max
	for _, c := range rep.Checks {
		rep.Score += c.Weight
	}
	pct := 0.0
	if max > 0 {
		pct = float64(rep.Score) / float64(max) * 100
	}
	rep.Grade = grade(pct)
	return rep
}

// hstsCheck memeriksa Strict-Transport-Security (hanya relevan atas HTTPS).
func hstsCheck(h http.Header, isHTTPS bool) Check {
	c := Check{
		Name:   "Strict-Transport-Security (HSTS)",
		Max:    20,
		Advice: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
	}
	v := h.Get("Strict-Transport-Security")
	if !isHTTPS {
		c.Status = StatusInfo
		c.Value = "HSTS dinilai hanya untuk target HTTPS"
		return c
	}
	if v == "" {
		c.Status = StatusFail
		return c
	}
	m := maxAgeRE.FindStringSubmatch(v)
	if m == nil {
		c.Status = StatusFail
		c.Value = truncate(v, 60)
		return c
	}
	age, _ := strconv.Atoi(m[1])
	c.Value = truncate(v, 60)
	switch {
	case age >= 31536000:
		c.Status = StatusPass
		c.Weight = 20
	case age >= 15552000:
		c.Status = StatusPartial
		c.Weight = 12
		c.Advice = "naikkan max-age ke >= 31536000 (1 tahun)"
	default:
		c.Status = StatusPartial
		c.Weight = 6
		c.Advice = "max-age terlalu pendek — gunakan >= 31536000"
	}
	return c
}

// cspDirectives mem-parse header Content-Security-Policy menjadi peta direktif.
func cspDirectives(h http.Header) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(h.Get("Content-Security-Policy"), ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, " ")
		out[strings.ToLower(name)] = val
	}
	return out
}

// cspCheck memeriksa Content-Security-Policy.
func cspCheck(h http.Header, dirs map[string]string) Check {
	c := Check{
		Name:   "Content-Security-Policy (CSP)",
		Max:    20,
		Advice: "Content-Security-Policy: default-src 'self'; object-src 'none'; base-uri 'self'",
	}
	if len(dirs) == 0 {
		c.Status = StatusFail
		return c
	}
	unsafe := false
	for _, d := range []string{"script-src", "default-src", "style-src"} {
		if val, ok := dirs[d]; ok &&
			(strings.Contains(val, "unsafe-inline") || strings.Contains(val, "unsafe-eval")) {
			unsafe = true
			break
		}
	}
	c.Value = truncate(h.Get("Content-Security-Policy"), 60)
	if unsafe {
		c.Status = StatusPartial
		c.Weight = 8
		c.Advice = "hilangkan 'unsafe-inline'/'unsafe-eval' — gunakan nonce/hash"
		return c
	}
	c.Status = StatusPass
	c.Weight = 20
	return c
}

// xctoCheck memeriksa X-Content-Type-Options.
func xctoCheck(h http.Header) Check {
	c := Check{Name: "X-Content-Type-Options", Max: 15, Advice: "X-Content-Type-Options: nosniff"}
	v := h.Get("X-Content-Type-Options")
	switch {
	case v == "":
		c.Status = StatusFail
	case strings.EqualFold(v, "nosniff"):
		c.Status = StatusPass
		c.Weight = 15
		c.Value = "nosniff"
	default:
		c.Status = StatusPartial
		c.Weight = 5
		c.Value = v
	}
	return c
}

// xfoCheck memeriksa X-Frame-Options (atau frame-ancestors di CSP).
func xfoCheck(h http.Header, dirs map[string]string) Check {
	c := Check{
		Name:   "X-Frame-Options / frame-ancestors",
		Max:    10,
		Advice: "X-Frame-Options: SAMEORIGIN (atau CSP: frame-ancestors 'none')",
	}
	if fa, ok := dirs["frame-ancestors"]; ok && fa != "" {
		c.Status = StatusPass
		c.Weight = 10
		c.Value = "CSP frame-ancestors " + fa
		return c
	}
	v := h.Get("X-Frame-Options")
	switch {
	case v == "":
		c.Status = StatusFail
	case strings.EqualFold(v, "DENY"), strings.EqualFold(v, "SAMEORIGIN"):
		c.Status = StatusPass
		c.Weight = 10
		c.Value = v
	case strings.EqualFold(v, "ALLOW-FROM"):
		c.Status = StatusPartial
		c.Weight = 5
		c.Value = v + " (deprecated)"
		c.Advice = "ALLOW-FROM sudah deprecated — gunakan CSP frame-ancestors"
	default:
		c.Status = StatusPartial
		c.Weight = 5
		c.Value = v
	}
	return c
}

// referrerCheck memeriksa Referrer-Policy.
func referrerCheck(h http.Header) Check {
	c := Check{Name: "Referrer-Policy", Max: 10, Advice: "Referrer-Policy: strict-origin-when-cross-origin"}
	v := h.Get("Referrer-Policy")
	switch v {
	case "":
		c.Status = StatusPartial
		c.Weight = 5
		c.Value = "(mengikuti default browser)"
	case "no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin":
		c.Status = StatusPass
		c.Weight = 10
		c.Value = v
	case "origin", "origin-when-cross-origin":
		c.Status = StatusPartial
		c.Weight = 8
		c.Value = v
	case "unsafe-url":
		c.Status = StatusFail
		c.Value = v
		c.Advice = "unsafe-url membocorkan URL penuh — ganti strict-origin-when-cross-origin"
	default:
		c.Status = StatusPartial
		c.Weight = 5
		c.Value = v
	}
	return c
}

// permissionsCheck memeriksa Permissions-Policy.
func permissionsCheck(h http.Header) Check {
	c := Check{
		Name:   "Permissions-Policy",
		Max:    10,
		Advice: "Permissions-Policy: camera=(), microphone=(), geolocation=()",
	}
	v := h.Get("Permissions-Policy")
	if v == "" {
		c.Status = StatusPartial
		c.Weight = 4
		return c
	}
	c.Status = StatusPass
	c.Weight = 10
	c.Value = truncate(v, 60)
	return c
}

// coopCheck memeriksa Cross-Origin-Opener-Policy.
func coopCheck(h http.Header) Check {
	c := Check{Name: "Cross-Origin-Opener-Policy (COOP)", Max: 5, Advice: "Cross-Origin-Opener-Policy: same-origin"}
	v := h.Get("Cross-Origin-Opener-Policy")
	switch v {
	case "same-origin", "same-origin-allow-popups":
		c.Status = StatusPass
		c.Weight = 5
		c.Value = v
	case "":
		c.Status = StatusFail
	default:
		c.Status = StatusPartial
		c.Weight = 3
		c.Value = v
	}
	return c
}

// coepCheck memeriksa Cross-Origin-Embedder-Policy.
func coepCheck(h http.Header) Check {
	c := Check{Name: "Cross-Origin-Embedder-Policy (COEP)", Max: 5, Advice: "Cross-Origin-Embedder-Policy: require-corp"}
	v := h.Get("Cross-Origin-Embedder-Policy")
	switch v {
	case "require-corp", "credentialless":
		c.Status = StatusPass
		c.Weight = 5
		c.Value = v
	case "":
		c.Status = StatusFail
	default:
		c.Status = StatusPartial
		c.Weight = 3
		c.Value = v
	}
	return c
}

// corpCheck memeriksa Cross-Origin-Resource-Policy.
func corpCheck(h http.Header) Check {
	c := Check{Name: "Cross-Origin-Resource-Policy (CORP)", Max: 5, Advice: "Cross-Origin-Resource-Policy: same-origin"}
	v := h.Get("Cross-Origin-Resource-Policy")
	switch v {
	case "same-origin":
		c.Status = StatusPass
		c.Weight = 5
		c.Value = v
	case "":
		c.Status = StatusFail
	case "same-site", "cross-origin":
		c.Status = StatusPartial
		c.Weight = 3
		c.Value = v
	default:
		c.Status = StatusPartial
		c.Weight = 3
		c.Value = v
	}
	return c
}

// grade mengubah persentase skor menjadi huruf nilai.
func grade(pct float64) string {
	switch {
	case pct >= 100:
		return "A+"
	case pct >= 90:
		return "A"
	case pct >= 80:
		return "A-"
	case pct >= 65:
		return "B"
	case pct >= 50:
		return "C"
	case pct >= 35:
		return "D"
	}
	return "F"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
