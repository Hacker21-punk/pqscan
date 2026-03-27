package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
)

const banner = `
 ╔══════════════════════════════════════════════════╗
 ║   ___  ___  ___                                  ║
 ║  | _ \/ _ \/ __|  ___ __ _ _ _                  ║
 ║  |  _/ (_) \__ \ / _/ _  | ' \                  ║
 ║  |_|  \__\_\___/ \__\__,_|_||_|                 ║
 ║                                                  ║
 ║  Post-Quantum Vulnerability Scanner v0.1.0       ║
 ║  "Find it before the quantum computer does"      ║
 ╚══════════════════════════════════════════════════╝
`

func printUsage() {
	fmt.Println(banner)
	cyan := color.New(color.FgCyan)
	white := color.New(color.FgWhite, color.Bold)

	white.Println("  USAGE:")
	cyan.Println("    pqscan <domain>                              Basic scan")
	cyan.Println("    pqscan --format json <domain>                 JSON output")
	cyan.Println("    pqscan --format html <domain>                 HTML report")
	cyan.Println("    pqscan --format html -o report.html <domain>  Save HTML to file")
	cyan.Println("    pqscan --format json -o report.json <domain>  Save JSON to file")
	cyan.Println("    pqscan --quiet <domain>                       Score only")
	fmt.Println()
	white.Println("  EXAMPLES:")
	cyan.Println("    pqscan google.com")
	cyan.Println("    pqscan --format html github.com")
	cyan.Println("    pqscan --format json -o report.json cloudflare.com")
	cyan.Println("    pqscan --quiet microsoft.com")
	fmt.Println()
}

func isFlag(s string) bool {
	return len(s) > 0 && s[0] == '-'
}

func main() {
	args := os.Args[1:]

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	format := "cli"
	outputFile := ""
	quiet := false
	var target string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--format", "-f":
			if i+1 < len(args) {
				format = args[i+1]
				i++
			}
		case "--output", "-o":
			if i+1 < len(args) {
				outputFile = args[i+1]
				i++
			}
		case "--quiet", "-q":
			quiet = true
		case "--help", "-h":
			printUsage()
			os.Exit(0)
		case "--version", "-v":
			fmt.Println("pqscan v0.1.0")
			os.Exit(0)
		default:
			if !isFlag(args[i]) {
				target = args[i]
			}
		}
	}

	if target == "" {
		printUsage()
		color.Red("  Error: no target specified")
		os.Exit(1)
	}

	if !quiet {
		fmt.Println(banner)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	results, err := ScanTarget(ctx, target)
	if err != nil {
		color.Red("  Error: %v", err)
		os.Exit(1)
	}

	// Output based on format
	switch format {
	case "json":
		err = PrintJSONReport(target, results, outputFile)
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}

	case "html":
		if outputFile == "" {
			outputFile = target + "-pqscan-report.html"
		}
		err = GenerateHTMLReport(target, results, outputFile)
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}

	case "cli":
		if quiet {
			vulnerable := 0
			for _, r := range results {
				if r.RiskLevel != "SAFE" {
					vulnerable++
				}
			}
			pct := float64(vulnerable) / float64(len(results)) * 100
			fmt.Printf("%.1f\n", pct)
		} else {
			PrintReport(target, results)
		}

	default:
		color.Red("  Unknown format: %s (use: cli, json, html)", format)
		os.Exit(1)
	}

	// Exit code 1 if critical findings (for CI/CD)
	for _, r := range results {
		if strings.Contains(r.RiskLevel, "CRITICAL") {
			os.Exit(1)
		}
	}
}