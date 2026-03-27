package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

type TargetResult struct {
	Target  string
	Results []ScanResult
	Error   error
}

type AggregateReport struct {
	Targets        []TargetResult
	TotalTargets   int
	TotalEndpoints int
	TotalCritical  int
	TotalHigh      int
	TotalModerate  int
	TotalSafe      int
	TotalVulnerable int
	OverallScore   float64
	ScanTime       time.Duration
}

// LoadTargetsFromFile reads a file with one domain per line
func LoadTargetsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("cannot open targets file: %w", err)
	}
	defer file.Close()

	var targets []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}

		// Remove protocol prefix if present
		line = strings.TrimPrefix(line, "https://")
		line = strings.TrimPrefix(line, "http://")

		// Remove trailing slash
		line = strings.TrimRight(line, "/")

		// Remove port if present (we scan our own ports)
		if idx := strings.Index(line, ":"); idx != -1 {
			line = line[:idx]
		}

		targets = append(targets, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading targets file: %w", err)
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found in %s", filename)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var unique []string
	for _, t := range targets {
		lower := strings.ToLower(t)
		if !seen[lower] {
			seen[lower] = true
			unique = append(unique, t)
		}
	}

	return unique, nil
}

// ScanMultipleTargets scans a list of targets concurrently
func ScanMultipleTargets(ctx context.Context, targets []string, workers int) AggregateReport {
	startTime := time.Now()

	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	dim := color.New(color.FgWhite)

	white.Printf("\n  Scanning %d targets with %d workers...\n\n", len(targets), workers)

	// Channel for targets to scan
	targetCh := make(chan string, len(targets))
	for _, t := range targets {
		targetCh <- t
	}
	close(targetCh)

	// Channel for results
	resultCh := make(chan TargetResult, len(targets))

	// Progress tracking
	var completed int
	var progressMu sync.Mutex
	total := len(targets)

	// Worker pool
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for target := range targetCh {
				// Create per-target context with timeout
				targetCtx, cancel := context.WithTimeout(ctx, 60*time.Second)

				results, err := ScanTarget(targetCtx, target)
				cancel()

				tr := TargetResult{
					Target:  target,
					Results: results,
					Error:   err,
				}

				resultCh <- tr

				// Update progress
				progressMu.Lock()
				completed++
				current := completed
				progressMu.Unlock()

				// Print progress
				pct := float64(current) / float64(total) * 100
				barWidth := 30
				filled := int(float64(barWidth) * float64(current) / float64(total))
				bar := strings.Repeat("█", filled) + strings.Repeat("░", barWidth-filled)

				if err != nil {
					red.Printf("  [%s] %d/%d  %5.1f%%  ✗ %s — %v\n",
						bar, current, total, pct, target, err)
				} else {
					// Count critical for this target
					crit := 0
					for _, r := range results {
						if strings.Contains(r.RiskLevel, "CRITICAL") {
							crit++
						}
					}
					if crit > 0 {
						red.Printf("  [%s] %d/%d  %5.1f%%  ✗ %s — %d critical findings\n",
							bar, current, total, pct, target, crit)
					} else {
						green.Printf("  [%s] %d/%d  %5.1f%%  ✓ %s — quantum safe\n",
							bar, current, total, pct, target)
					}
				}
			}
		}()
	}

	// Wait for all workers to finish
	wg.Wait()
	close(resultCh)

	// Collect all results
	var allResults []TargetResult
	for tr := range resultCh {
		allResults = append(allResults, tr)
	}

	// Build aggregate report
	report := AggregateReport{
		Targets:      allResults,
		TotalTargets: len(targets),
		ScanTime:     time.Since(startTime),
	}

	for _, tr := range allResults {
		if tr.Error != nil {
			continue
		}
		for _, r := range tr.Results {
			report.TotalEndpoints++
			switch {
			case strings.Contains(r.RiskLevel, "CRITICAL"):
				report.TotalCritical++
			case strings.Contains(r.RiskLevel, "HIGH"):
				report.TotalHigh++
			case strings.Contains(r.RiskLevel, "MODERATE"):
				report.TotalModerate++
			case r.RiskLevel == "SAFE":
				report.TotalSafe++
			default:
				report.TotalCritical++
			}
		}
	}

	report.TotalVulnerable = report.TotalEndpoints - report.TotalSafe
	if report.TotalEndpoints > 0 {
		report.OverallScore = float64(report.TotalVulnerable) / float64(report.TotalEndpoints) * 100
	}

	fmt.Println()
	dim.Printf("  Scan completed in %s\n", report.ScanTime.Round(time.Millisecond))
	cyan.Printf("  Scanned %d targets, %d endpoints\n\n", report.TotalTargets, report.TotalEndpoints)

	return report
}

// PrintAggregateReport prints the multi-target CLI report
func PrintAggregateReport(report AggregateReport) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	cyan := color.New(color.FgCyan)
	dim := color.New(color.FgWhite)

	// Aggregate summary box
	fmt.Println(" ╔═══════════════════════════════════════════════════════════╗")
	fmt.Println(" ║         PQScan — Aggregate Quantum Risk Report           ║")
	fmt.Println(" ╠═══════════════════════════════════════════════════════════╣")
	fmt.Println(" ║                                                           ║")
	white.Printf(" ║  Targets scanned:     %-35d║\n", report.TotalTargets)
	white.Printf(" ║  Total endpoints:     %-35d║\n", report.TotalEndpoints)

	if report.TotalVulnerable > 0 {
		red.Printf(" ║  Quantum-vulnerable:  %-4d (%.1f%%)%-27s║\n",
			report.TotalVulnerable, report.OverallScore, "")
	} else {
		green.Printf(" ║  Quantum-vulnerable:  0    (0.0%%)%-27s║\n", "")
	}

	white.Printf(" ║  Scan duration:       %-35s║\n",
		report.ScanTime.Round(time.Millisecond).String())

	fmt.Println(" ║                                                           ║")

	// Risk bar
	score := report.OverallScore
	barLen := int(score / 100 * 35)
	if barLen > 35 {
		barLen = 35
	}
	bar := strings.Repeat("█", barLen) + strings.Repeat("░", 35-barLen)

	if score > 70 {
		red.Printf(" ║  Risk Score: %5.1f / 100   CRITICAL%-22s║\n", score, "")
		red.Printf(" ║  %s%-20s║\n", bar, "")
	} else if score > 30 {
		yellow.Printf(" ║  Risk Score: %5.1f / 100   HIGH%-26s║\n", score, "")
		yellow.Printf(" ║  %s%-20s║\n", bar, "")
	} else if score > 0 {
		yellow.Printf(" ║  Risk Score: %5.1f / 100   MODERATE%-22s║\n", score, "")
		yellow.Printf(" ║  %s%-20s║\n", bar, "")
	} else {
		green.Printf(" ║  Risk Score: %5.1f / 100   SAFE%-26s║\n", score, "")
		green.Printf(" ║  %s%-20s║\n", bar, "")
	}

	fmt.Println(" ║                                                           ║")
	red.Printf(   " ║  🔴 Critical:  %-6d  Broken by quantum computer%-9s║\n", report.TotalCritical, "")
	yellow.Printf(" ║  🟠 High:      %-6d  Severely weakened%-19s║\n", report.TotalHigh, "")
	dim.Printf(   " ║  🟡 Moderate:  %-6d  Weakened but usable%-17s║\n", report.TotalModerate, "")
	green.Printf( " ║  🟢 Safe:      %-6d  Quantum-resistant%-19s║\n", report.TotalSafe, "")
	fmt.Println(" ║                                                           ║")
	fmt.Println(" ╚═══════════════════════════════════════════════════════════╝")
	fmt.Println()

	// Per-target breakdown
	white.Println(" PER-TARGET BREAKDOWN:")
	fmt.Println(" " + strings.Repeat("─", 60))
	fmt.Println()

	// Sort: most vulnerable first
	for _, tr := range report.Targets {
		if tr.Error != nil {
			red.Printf("   ✗ %-30s ERROR: %v\n", tr.Target, tr.Error)
			continue
		}

		targetCritical := 0
		targetSafe := 0
		targetTotal := len(tr.Results)

		for _, r := range tr.Results {
			if strings.Contains(r.RiskLevel, "CRITICAL") {
				targetCritical++
			} else if r.RiskLevel == "SAFE" {
				targetSafe++
			}
		}

		targetVuln := targetTotal - targetSafe
		targetPct := 0.0
		if targetTotal > 0 {
			targetPct = float64(targetVuln) / float64(targetTotal) * 100
		}

		// Mini bar for each target
		miniBarLen := int(targetPct / 100 * 15)
		if miniBarLen > 15 {
			miniBarLen = 15
		}
		miniBar := strings.Repeat("█", miniBarLen) + strings.Repeat("░", 15-miniBarLen)

		if targetCritical > 0 {
			red.Printf("   🔴 %-25s %s  %5.1f%%  %d/%d vulnerable\n",
				tr.Target, miniBar, targetPct, targetVuln, targetTotal)
		} else {
			green.Printf("   🟢 %-25s %s  %5.1f%%  quantum safe\n",
				tr.Target, miniBar, targetPct)
		}
	}

	fmt.Println()
	fmt.Println(" " + strings.Repeat("─", 60))

	// Print detailed findings per target
	white.Println("\n DETAILED FINDINGS BY TARGET:")
	fmt.Println(" " + strings.Repeat("─", 60))

	for _, tr := range report.Targets {
		if tr.Error != nil {
			continue
		}

		fmt.Println()
		cyan.Printf(" ┌─ %s ", tr.Target)
		fmt.Printf("(%d endpoints)\n", len(tr.Results))

		for i, r := range tr.Results {
			prefix := " │"
			if i == len(tr.Results)-1 {
				prefix = " └"
			}

			switch {
			case strings.Contains(r.RiskLevel, "CRITICAL"):
				red.Printf("%s  🔴 :%d/%s — %s\n",
					prefix, r.Port, r.Service, r.CipherSuite)
				dim.Printf(" │     Threat: %s\n", r.QuantumThreat)
				yellow.Printf(" │     Fix: %s\n", r.Remediation)
			case r.RiskLevel == "SAFE":
				green.Printf("%s  🟢 :%d/%s — %s\n",
					prefix, r.Port, r.Service, r.CipherSuite)
			default:
				yellow.Printf("%s  🟡 :%d/%s — %s\n",
					prefix, r.Port, r.Service, r.CipherSuite)
			}
		}
	}

	// CNSA warning
	fmt.Println()
	fmt.Println(" " + strings.Repeat("─", 60))
	if report.TotalCritical > 0 {
		white.Println(" CNSA 2.0 COMPLIANCE:")
		red.Println("   ALL TARGETS FAILING — Migration required before 2033")
		fmt.Println()
		yellow.Println(" ⚠ HARVEST NOW, DECRYPT LATER:")
		yellow.Println("   Encrypted traffic across ALL scanned targets is at risk")
		yellow.Println("   of future quantum decryption.")
	} else {
		green.Println(" CNSA 2.0 COMPLIANCE: ALL TARGETS PASSING ✅")
	}

	// Footer
	fmt.Println()
	fmt.Println(" " + strings.Repeat("═", 60))
	dim.Println(" Generated by pqscan v0.1.0")
	dim.Println(" https://github.com/yourorg/pqscan")
	fmt.Println()
}

// FlattenResults collects all results from all targets into one slice
func FlattenResults(report AggregateReport) []ScanResult {
	var all []ScanResult
	for _, tr := range report.Targets {
		if tr.Error == nil {
			all = append(all, tr.Results...)
		}
	}
	return all
}