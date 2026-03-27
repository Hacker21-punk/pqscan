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
	cyan.Println("    pqscan <domain1> <domain2> <domain3>          Multiple targets")
	cyan.Println("    pqscan --targets servers.txt                  Scan from file")
	cyan.Println("    pqscan --format json <domain>                 JSON output")
	cyan.Println("    pqscan --format html <domain>                 HTML report")
	cyan.Println("    pqscan --format html -o report.html <domain>  Save HTML to file")
	cyan.Println("    pqscan --workers 10 --targets servers.txt     Control concurrency")
	cyan.Println("    pqscan --quiet <domain>                       Score only")
	fmt.Println()
	white.Println("  EXAMPLES:")
	cyan.Println("    pqscan google.com")
	cyan.Println("    pqscan google.com github.com cloudflare.com")
	cyan.Println("    pqscan --targets my-servers.txt")
	cyan.Println("    pqscan --format html --targets servers.txt")
	cyan.Println("    pqscan --format json -o report.json --targets servers.txt")
	cyan.Println("    pqscan --quiet microsoft.com")
	fmt.Println()
	white.Println("  TARGET FILE FORMAT (one domain per line):")
	cyan.Println("    google.com")
	cyan.Println("    github.com")
	cyan.Println("    # this is a comment")
	cyan.Println("    cloudflare.com")
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

	// Parse flags
	format := "cli"
	outputFile := ""
	targetsFile := ""
	quiet := false
	workers := 3
	var targets []string

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
		case "--targets", "-t":
			if i+1 < len(args) {
				targetsFile = args[i+1]
				i++
			}
		case "--workers", "-w":
			if i+1 < len(args) {
				fmt.Sscanf(args[i+1], "%d", &workers)
				if workers < 1 {
					workers = 1
				}
				if workers > 20 {
					workers = 20
				}
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
				targets = append(targets, args[i])
			}
		}
	}

	// Load targets from file if specified
	if targetsFile != "" {
		fileTargets, err := LoadTargetsFromFile(targetsFile)
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}
		targets = append(targets, fileTargets...)
	}

	// Deduplicate targets
	targets = deduplicateTargets(targets)

	if len(targets) == 0 {
		printUsage()
		color.Red("  Error: no targets specified")
		os.Exit(1)
	}

	if !quiet {
		fmt.Println(banner)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// Single target mode
	if len(targets) == 1 {
		results, err := ScanTarget(ctx, targets[0])
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}

		switch format {
		case "json":
			err = PrintJSONReport(targets[0], results, outputFile)
		case "html":
			if outputFile == "" {
				outputFile = targets[0] + "-pqscan-report.html"
			}
			err = GenerateHTMLReport(targets[0], results, outputFile)
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
				PrintReport(targets[0], results)
			}
		default:
			color.Red("  Unknown format: %s (use: cli, json, html)", format)
			os.Exit(1)
		}

		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}

		// Exit code for CI/CD
		for _, r := range results {
			if strings.Contains(r.RiskLevel, "CRITICAL") {
				os.Exit(1)
			}
		}
		return
	}

	// Multi-target mode
	report := ScanMultipleTargets(ctx, targets, workers)

	switch format {
	case "json":
		allResults := FlattenResults(report)
		err := PrintJSONReport("multiple-targets", allResults, outputFile)
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}

	case "html":
		if outputFile == "" {
			outputFile = "pqscan-aggregate-report.html"
		}
		err := GenerateAggregateHTMLReport(report, outputFile)
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}

	case "cli":
		if quiet {
			fmt.Printf("%.1f\n", report.OverallScore)
		} else {
			PrintAggregateReport(report)
		}

	default:
		color.Red("  Unknown format: %s (use: cli, json, html)", format)
		os.Exit(1)
	}

	// Exit code for CI/CD
	if report.TotalCritical > 0 {
		os.Exit(1)
	}
}

func deduplicateTargets(targets []string) []string {
	seen := make(map[string]bool)
	var unique []string
	for _, t := range targets {
		lower := strings.ToLower(strings.TrimSpace(t))
		if lower != "" && !seen[lower] {
			seen[lower] = true
			unique = append(unique, t)
		}
	}
	return unique
}