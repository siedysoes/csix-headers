// csix-headers: pemeriksa & penilai security headers website.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/siedysoes/csix-headers/internal/check"
	"github.com/siedysoes/csix-headers/internal/ui"
)

func main() {
	var (
		jsonOut     bool
		insecure    bool
		noColor     bool
		showVersion bool
		minScore    int
		timeout     time.Duration
	)
	flag.BoolVar(&jsonOut, "json", false, "output JSON")
	flag.IntVar(&minScore, "min-score", 65, "skor minimal lolos (di bawah ini exit 1)")
	flag.DurationVar(&timeout, "timeout", 10*time.Second, "timeout HTTP request")
	flag.BoolVar(&insecure, "insecure", false, "abaikan verifikasi sertifikat TLS")
	flag.BoolVar(&noColor, "no-color", false, "matikan warna output")
	flag.BoolVar(&showVersion, "version", false, "tampilkan versi")
	flag.Parse()

	if showVersion {
		fmt.Println("csix-headers v" + check.Version)
		return
	}
	if !noColor {
		ui.Setup()
	}

	if flag.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "penggunaan: csix-headers <url>   (contoh: csix-headers https://example.com)")
		fmt.Fprintln(os.Stderr, "           csix-headers --json <url>")
		os.Exit(2)
	}
	raw := flag.Arg(0)

	target, headers, err := check.Fetch(raw, timeout, insecure)
	if err != nil {
		fatal("gagal mengambil " + raw + ": " + err.Error())
	}
	rep := check.Evaluate(target, headers)

	if jsonOut {
		b, err := json.MarshalIndent(map[string]any{
			"tool":    "csix-headers",
			"version": check.Version,
			"report":  rep,
		}, "", "  ")
		if err != nil {
			fatal(err.Error())
		}
		fmt.Println(string(b))
	} else {
		printReport(rep, raw, target.String() != raw)
	}

	if rep.Score < minScore {
		os.Exit(1)
	}
}

func printReport(rep check.Report, original string, redirected bool) {
	fmt.Println(ui.Wrap(ui.Bold, "csix-headers v"+check.Version) + ui.Wrap(ui.Gray, " — pemeriksa security headers"))
	fmt.Println()

	gradeColor := ui.Green
	switch rep.Grade {
	case "B", "C":
		gradeColor = ui.Yellow
	case "D", "F":
		gradeColor = ui.Red
	}

	fmt.Printf("  %-8s %s\n", "Target", ui.Wrap(ui.Gray, original))
	if redirected {
		fmt.Printf("  %-8s %s\n", "Final", ui.Wrap(ui.Gray, rep.URL))
	}
	fmt.Printf("  %-8s %d/%d   Grade %s\n", "Skor", rep.Score, rep.Max, ui.Wrap(ui.Bold+";"+gradeColor, rep.Grade))
	fmt.Println(ui.Wrap(ui.Gray, strings.Repeat("─", 58)))

	for _, c := range rep.Checks {
		icon, color := "✗", ui.Red
		switch c.Status {
		case check.StatusPass:
			icon, color = "✓", ui.Green
		case check.StatusPartial:
			icon, color = "~", ui.Yellow
		case check.StatusInfo:
			icon, color = "•", ui.Gray
		}
		if c.Status == check.StatusInfo {
			fmt.Printf("  %s %-40s %s\n", icon, c.Name, ui.Wrap(ui.Gray, c.Value))
			continue
		}
		weight := ui.Wrap(color, fmt.Sprintf("%2d", c.Weight))
		fmt.Printf("  %s %-40s %s/%d", icon, c.Name, weight, c.Max)
		if c.Value != "" {
			fmt.Print(ui.Wrap(ui.Gray, "  "+c.Value))
		}
		fmt.Println()
		if (c.Status == check.StatusFail || c.Status == check.StatusPartial) && c.Advice != "" {
			fmt.Println(ui.Wrap(ui.Gray, "      → "+c.Advice))
		}
	}

	if len(rep.Notes) > 0 {
		fmt.Println()
		fmt.Println(ui.Wrap(ui.Gray, "Catatan:"))
		for _, n := range rep.Notes {
			fmt.Println(ui.Wrap(ui.Gray, "  • "+n))
		}
	}
	fmt.Println()
	fmt.Println(ui.Wrap(ui.Gray, "grade: A+ 100 · A 90 · A- 80 · B 65 · C 50 · D 35 · F <35 (persentase dari skor maksimal)"))
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, ui.Wrap(ui.Red, "error: ")+msg)
	os.Exit(2)
}
