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
	cyan.Println("    pqscan --chain <domain>                      Deep cert chain analysis")
	cyan.Println("    pqscan --enumerate <domain>                  Discover subdomains first")
	cyan.Println("    pqscan <domain1> <domain2> <domain3>          Multiple targets")
	cyan.Println("    pqscan --targets servers.txt                  Scan from file")
	cyan.Println("    pqscan --format json <domain>                 JSON output")
	cyan.Println("    pqscan --format html <domain>                 HTML report")
	cyan.Println("    pqscan --format pdf <domain>                  PDF report")
	cyan.Println("    pqscan --format cbom <domain>                 CBOM output (CycloneDX)")
	cyan.Println("    pqscan --format html -o report.html <domain>  Save HTML to file")
	cyan.Println("    pqscan --format pdf -o report.pdf <domain>    Save PDF to file")
	cyan.Println("    pqscan --format cbom -o cbom.json <domain>    Save CBOM to file")
	cyan.Println("    pqscan --workers 10 --targets servers.txt     Control concurrency")
	cyan.Println("    pqscan --quiet <domain>                       Score only")
	fmt.Println()
	white.Println("  FORMATS:")
	cyan.Println("    cli    Terminal output (default)")
	cyan.Println("    json   Machine-readable JSON")
	cyan.Println("    html   Beautiful HTML report")
	cyan.Println("    pdf    Executive PDF report")
	cyan.Println("    cbom   CycloneDX Cryptographic Bill of Materials")
	fmt.Println()
	white.Println("  EXAMPLES:")
	cyan.Println("    pqscan google.com")
	cyan.Println("    pqscan --chain google.com")
	cyan.Println("    pqscan --chain --enumerate example.com")
	cyan.Println("    pqscan --enumerate google.com")
	cyan.Println("    pqscan google.com github.com cloudflare.com")
	cyan.Println("    pqscan --format html --chain google.com")
	cyan.Println("    pqscan --format pdf -o executive-report.pdf google.com")
	cyan.Println("    pqscan --format cbom -o inventory.json google.com")
	cyan.Println("    pqscan --quiet microsoft.com")
	fmt.Println()
	white.Println("  CHAIN ANALYSIS MODE:")
	cyan.Println("    Performs deep analysis of the entire certificate chain:")
	cyan.Println("      • Root CA → Intermediate → Leaf certificate")
	cyan.Println("      • Key algorithm and size for EVERY cert")
	cyan.Println("      • Signature algorithm analysis")
	cyan.Println("      • PQC / hybrid certificate detection")
	fmt.Println()
	white.Println("  ENUMERATE MODE:")
	cyan.Println("    Discovers subdomains using:")
	cyan.Println("      • Certificate Transparency logs (crt.sh)")
	cyan.Println("      • DNS brute-force (200 common subdomains)")
	cyan.Println("      • DNS records (MX, NS, SRV, TXT/SPF)")
	fmt.Println()
	white.Println("  CBOM (Cryptographic Bill of Materials):")
	cyan.Println("    Machine-readable inventory of all cryptographic assets.")
	cyan.Println("    CycloneDX v1.6 format — compatible with:")
	cyan.Println("      • OWASP Dependency-Track")
	cyan.Println("      • IBM Quantum Safe Explorer")
	cyan.Println("      • Security compliance platforms")
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
	targetsFile := ""
	quiet := false
	enumerate := false
	chainAnalysis := false
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
		case "--enumerate", "-e":
			enumerate = true
		case "--chain", "-c":
			chainAnalysis = true
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

	if targetsFile != "" {
		fileTargets, err := LoadTargetsFromFile(targetsFile)
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}
		targets = append(targets, fileTargets...)
	}

	targets = deduplicateTargets(targets)

	if len(targets) == 0 {
		printUsage()
		color.Red("  Error: no targets specified")
		os.Exit(1)
	}

	if !quiet {
		fmt.Println(banner)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Second)
	defer cancel()

	if enumerate {
		var allSubdomains []string
		for _, target := range targets {
			subs, err := EnumerateSubdomains(ctx, target)
			if err != nil {
				color.Red("  Error enumerating %s: %v", target, err)
				allSubdomains = append(allSubdomains, target)
				continue
			}
			allSubdomains = append(allSubdomains, subs...)
		}
		targets = deduplicateTargets(allSubdomains)

		if !quiet {
			white := color.New(color.FgWhite, color.Bold)
			white.Printf("  Starting scan of %d discovered subdomains...\n\n", len(targets))
		}
	}

	// Single target
	if len(targets) == 1 {
		results, err := ScanTarget(ctx, targets[0])
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}

		if chainAnalysis {
			chain, chainErr := AnalyzeCertificateChain(targets[0], 443)
			if chainErr != nil {
				color.Yellow("  ⚠ Chain analysis failed: %v", chainErr)
			} else {
				PrintCertChainReport(chain)
			}
		}

		outputResults(format, outputFile, targets[0], results, quiet)

		for _, r := range results {
			if strings.Contains(r.RiskLevel, "CRITICAL") {
				os.Exit(1)
			}
		}
		return
	}

	// Multi-target
	report := ScanMultipleTargets(ctx, targets, workers)

	if chainAnalysis && format == "cli" && !quiet {
		white := color.New(color.FgWhite, color.Bold)
		white.Println("\n CERTIFICATE CHAIN ANALYSIS (per target):")
		fmt.Println(" " + strings.Repeat("═", 55))

		for _, tr := range report.Targets {
			if tr.Error != nil {
				continue
			}
			chain, err := AnalyzeCertificateChain(tr.Target, 443)
			if err != nil {
				color.Yellow("  ⚠ %s: chain analysis failed: %v\n", tr.Target, err)
				continue
			}
			PrintCertChainReport(chain)
		}
	}

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

	case "pdf":
		if outputFile == "" {
			outputFile = "pqscan-aggregate-report.pdf"
		}
		allResults := FlattenResults(report)
		err := GeneratePDFReport("multiple-targets", allResults, outputFile)
		if err != nil {
			color.Red("  Error: %v", err)
			os.Exit(1)
		}

	case "cbom":
		if outputFile == "" {
			outputFile = "pqscan-aggregate-cbom.json"
		}
		allResults := FlattenResults(report)
		err := GenerateCBOM("multiple-targets", allResults, outputFile)
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
		color.Red("  Unknown format: %s (use: cli, json, html, pdf, cbom)", format)
		os.Exit(1)
	}

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
			unique = append(unique, lower)
		}
	}
	return unique
}

func outputResults(format, outputFile, target string, results []ScanResult, quiet bool) {
	var err error

	switch format {
	case "json":
		err = PrintJSONReport(target, results, outputFile)
	case "html":
		if outputFile == "" {
			outputFile = target + "-pqscan-report.html"
		}
		err = GenerateHTMLReport(target, results, outputFile)
	case "pdf":
		if outputFile == "" {
			outputFile = target + "-pqscan-report.pdf"
		}
		err = GeneratePDFReport(target, results, outputFile)
	case "cbom":
		if outputFile == "" {
			outputFile = target + "-cbom.json"
		}
		err = GenerateCBOM(target, results, outputFile)
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
		color.Red("  Unknown format: %s (use: cli, json, html, pdf, cbom)", format)
		os.Exit(1)
	}

	if err != nil {
		color.Red("  Error: %v", err)
		os.Exit(1)
	}
}