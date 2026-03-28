package main

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

func PrintReport(target string, results []ScanResult) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	cyan := color.New(color.FgCyan)
	dim := color.New(color.FgWhite)

	// Sort results: critical first, then by port
	sort.Slice(results, func(i, j int) bool {
		if results[i].RiskLevel != results[j].RiskLevel {
			return riskPriority(results[i].RiskLevel) > riskPriority(results[j].RiskLevel)
		}
		return results[i].Port < results[j].Port
	})

	// Count results by risk
	critical := 0
	high := 0
	moderate := 0
	safe := 0
	total := len(results)

	for _, r := range results {
		switch {
		case strings.Contains(r.RiskLevel, "CRITICAL"):
			critical++
		case strings.Contains(r.RiskLevel, "HIGH"):
			high++
		case strings.Contains(r.RiskLevel, "MODERATE"):
			moderate++
		case r.RiskLevel == "SAFE":
			safe++
		default:
			critical++ // assume worst case
		}
	}

	vulnerable := total - safe
	pct := 0.0
	if total > 0 {
		pct = float64(vulnerable) / float64(total) * 100
	}
	score := pct

	// Count unique services
	services := make(map[string]bool)
	for _, r := range results {
		services[r.Service] = true
	}

	// Print summary box
	fmt.Println()
	fmt.Println(" ╔═══════════════════════════════════════════════════════╗")
	fmt.Println(" ║            PQScan — Quantum Risk Report               ║")
	fmt.Println(" ╠═══════════════════════════════════════════════════════╣")
	fmt.Println(" ║                                                       ║")
	white.Printf(" ║  Target:              %-32s║\n", target)
	dim.Printf(  " ║  Scan time:           %-32s║\n",
		time.Now().Format("2006-01-02 15:04:05 MST"))
	white.Printf(" ║  Services found:      %-32d║\n", len(services))
	white.Printf(" ║  Endpoints scanned:   %-32d║\n", total)

	if vulnerable > 0 {
		red.Printf(" ║  Quantum-vulnerable:  %-4d (%.1f%%)%-24s║\n",
			vulnerable, pct, "")
	} else {
		green.Printf(" ║  Quantum-vulnerable:  0    (0.0%%)%-24s║\n", "")
	}

	fmt.Println(" ║                                                       ║")

	// Risk score with visual bar
	barLen := int(score / 100 * 30)
	if barLen > 30 {
		barLen = 30
	}
	bar := strings.Repeat("█", barLen) + strings.Repeat("░", 30-barLen)

	if score > 70 {
		red.Printf(" ║  Risk Score: %5.1f / 100   CRITICAL%-20s║\n", score, "")
		red.Printf(" ║  %s  %-4s║\n", bar, "")
	} else if score > 30 {
		yellow.Printf(" ║  Risk Score: %5.1f / 100   HIGH%-24s║\n", score, "")
		yellow.Printf(" ║  %s  %-4s║\n", bar, "")
	} else if score > 0 {
		yellow.Printf(" ║  Risk Score: %5.1f / 100   MODERATE%-20s║\n", score, "")
		yellow.Printf(" ║  %s  %-4s║\n", bar, "")
	} else {
		green.Printf(" ║  Risk Score: %5.1f / 100   SAFE%-24s║\n", score, "")
		green.Printf(" ║  %s  %-4s║\n", bar, "")
	}

	fmt.Println(" ║                                                       ║")
	red.Printf(   " ║  🔴 Critical:  %-5d   Broken by quantum computer%-4s║\n", critical, "")
	yellow.Printf(" ║  🟠 High:      %-5d   Severely weakened%-14s║\n", high, "")
	dim.Printf(   " ║  🟡 Moderate:  %-5d   Weakened but usable%-12s║\n", moderate, "")
	green.Printf( " ║  🟢 Safe:      %-5d   Quantum-resistant%-14s║\n", safe, "")
	fmt.Println(" ║                                                       ║")
	fmt.Println(" ╚═══════════════════════════════════════════════════════╝")
	fmt.Println()

	// Service breakdown
	white.Println(" SERVICE BREAKDOWN:")
	fmt.Println(" " + strings.Repeat("─", 55))

	serviceResults := make(map[string][]ScanResult)
	for _, r := range results {
		serviceResults[r.Service] = append(serviceResults[r.Service], r)
	}

	for service, svcResults := range serviceResults {
		svcCritical := 0
		svcSafe := 0
		for _, r := range svcResults {
			if strings.Contains(r.RiskLevel, "CRITICAL") {
				svcCritical++
			} else if r.RiskLevel == "SAFE" {
				svcSafe++
			}
		}

		if svcCritical > 0 {
			red.Printf("   %-15s %d endpoint(s)   🔴 VULNERABLE\n",
				service, len(svcResults))
		} else {
			green.Printf("   %-15s %d endpoint(s)   🟢 SAFE\n",
				service, len(svcResults))
		}
	}

	fmt.Println()

	// Detailed findings
	white.Println(" DETAILED FINDINGS:")
	fmt.Println(" " + strings.Repeat("─", 55))

	for i, r := range results {
		fmt.Println()

		// Risk indicator and finding header
		switch {
		case strings.Contains(r.RiskLevel, "CRITICAL"):
			red.Printf(" 🔴 Finding #%d — %s:%d (%s)\n",
				i+1, r.Host, r.Port, r.Service)
		case r.RiskLevel == "SAFE":
			green.Printf(" 🟢 Finding #%d — %s:%d (%s)\n",
				i+1, r.Host, r.Port, r.Service)
		default:
			yellow.Printf(" 🟡 Finding #%d — %s:%d (%s)\n",
				i+1, r.Host, r.Port, r.Service)
		}

		cyan.Printf("    Protocol:       %s\n", r.Protocol)
		cyan.Printf("    Cipher Suite:   %s\n", r.CipherSuite)
		cyan.Printf("    Key Exchange:   %s\n", r.KeyExchange)

		// Certificate details
		if r.Certificate.Subject != "" {
			fmt.Println()
			dim.Printf("    Certificate:\n")
			cyan.Printf("      Subject:      %s\n", r.Certificate.Subject)
			cyan.Printf("      Issuer:       %s\n", r.Certificate.Issuer)
			cyan.Printf("      Key Type:     %s", r.Certificate.KeyAlgorithm)
			if r.Certificate.KeySize > 0 {
				cyan.Printf(" (%d-bit)", r.Certificate.KeySize)
			}
			fmt.Println()
			cyan.Printf("      Signature:    %s\n", r.Certificate.SignatureAlg)
			cyan.Printf("      Expires:      %s",
				r.Certificate.NotAfter.Format("2006-01-02"))

			// Days until expiry
			daysLeft := int(time.Until(r.Certificate.NotAfter).Hours() / 24)
			if daysLeft < 30 {
				red.Printf(" (%d days!)", daysLeft)
			} else if daysLeft < 90 {
				yellow.Printf(" (%d days)", daysLeft)
			} else {
				dim.Printf(" (%d days)", daysLeft)
			}
			fmt.Println()

			// Certificate quantum risk
			certRisk := classifyCertRisk(r.Certificate.KeyAlgorithm)
			if strings.Contains(certRisk, "CRITICAL") {
				red.Printf("      Quantum Risk: %s\n", certRisk)
			} else if strings.Contains(certRisk, "SAFE") {
				green.Printf("      Quantum Risk: %s\n", certRisk)
			} else {
				yellow.Printf("      Quantum Risk: %s\n", certRisk)
			}

			// Show SANs if present
			if len(r.Certificate.SANs) > 0 && len(r.Certificate.SANs) <= 5 {
				dim.Printf("      SANs:         %s\n",
					strings.Join(r.Certificate.SANs, ", "))
			} else if len(r.Certificate.SANs) > 5 {
				dim.Printf("      SANs:         %s (+%d more)\n",
					strings.Join(r.Certificate.SANs[:3], ", "),
					len(r.Certificate.SANs)-3)
			}
		}

		// Error warnings
		if r.Error != "" {
			fmt.Println()
			yellow.Printf("    ⚠ Warning:      %s\n", r.Error)
		}

		// Risk assessment
		fmt.Println()
		if strings.Contains(r.RiskLevel, "CRITICAL") {
			red.Printf("    RISK:           %s\n", r.RiskLevel)
			red.Printf("    THREAT:         %s\n", r.QuantumThreat)
		} else if r.RiskLevel == "SAFE" {
			green.Printf("    RISK:           %s\n", r.RiskLevel)
			green.Printf("    THREAT:         None\n")
		} else {
			yellow.Printf("    RISK:           %s\n", r.RiskLevel)
			yellow.Printf("    THREAT:         %s\n", r.QuantumThreat)
		}

		yellow.Printf("    FIX:            %s\n", r.Remediation)
	}

	// CNSA 2.0 timeline
	fmt.Println()
	fmt.Println(" " + strings.Repeat("─", 55))
	white.Println(" CNSA 2.0 COMPLIANCE TIMELINE:")
	fmt.Println()

	type milestone struct {
		year string
		desc string
	}

	milestones := []milestone{
		{"2025", "Prefer PQC for new systems"},
		{"2027", "New systems MUST use PQC"},
		{"2030", "Legacy crypto must begin migration"},
		{"2033", "All protocols must be quantum-safe"},
		{"2035", "Complete migration — no exceptions"},
	}

	for _, m := range milestones {
		if critical > 0 {
			red.Printf("    %s  %-40s ❌ FAILING\n", m.year, m.desc)
		} else {
			green.Printf("    %s  %-40s ✅ PASSING\n", m.year, m.desc)
		}
	}

	// HNDL warning
	fmt.Println()
	fmt.Println(" " + strings.Repeat("─", 55))
	white.Println(" ⚠  HARVEST NOW, DECRYPT LATER (HNDL) RISK:")
	fmt.Println()

	if critical > 0 {
		red.Println("    Status: CRITICAL")
		fmt.Println()
		yellow.Println("    Nation-state adversaries are ALREADY recording encrypted")
		yellow.Println("    traffic. When quantum computers become available, they")
		yellow.Println("    will decrypt everything captured today.")
		fmt.Println()
		yellow.Println("    Any data that must remain confidential for >10 years")
		yellow.Println("    is ALREADY at risk. This includes:")
		yellow.Println("      • Trade secrets & intellectual property")
		yellow.Println("      • Health records (HIPAA: 50+ year retention)")
		yellow.Println("      • Financial records (7+ year retention)")
		yellow.Println("      • Attorney-client communications")
		yellow.Println("      • Government classified information")
	} else {
		green.Println("    Status: LOW — Post-quantum algorithms in use")
	}

	// Migration estimate
	fmt.Println()
	fmt.Println(" " + strings.Repeat("─", 55))
	white.Println(" MIGRATION ESTIMATE:")
	fmt.Println()

	if critical > 0 {
		configChanges := 0
		hardChanges := 0
		for _, r := range results {
			if strings.Contains(r.RiskLevel, "CRITICAL") {
				switch r.Service {
				case "HTTPS", "HTTPS-Alt":
					configChanges++
				case "SSH", "SSH-Alt":
					configChanges++
				default:
					hardChanges++
				}
			}
		}
		cyan.Printf("    Configuration changes needed:  %d\n", configChanges)
		cyan.Printf("    Complex migrations needed:     %d\n", hardChanges)

		totalWork := configChanges + hardChanges*3
		if totalWork < 10 {
			cyan.Println("    Estimated effort:              1-2 weeks")
		} else if totalWork < 50 {
			cyan.Println("    Estimated effort:              1-3 months")
		} else {
			cyan.Println("    Estimated effort:              6-18 months")
		}
	} else {
		green.Println("    No migration needed — already quantum-safe! 🎉")
	}

	// Footer
	fmt.Println()
	fmt.Println(" " + strings.Repeat("═", 55))
	dim.Println(" Generated by pqscan v0.1.0")
	dim.Println(" https://github.com/Hacker21-punk/pqscan")
	fmt.Println()
	yellow.Println(" Want automated migration?")
	cyan.Println(" → https://github.com/Hacker21-punk/pqscan")
	fmt.Println()
}

func riskPriority(risk string) int {
	switch {
	case strings.Contains(risk, "CRITICAL"):
		return 100
	case strings.Contains(risk, "HIGH"):
		return 75
	case strings.Contains(risk, "MODERATE"):
		return 50
	case risk == "SAFE":
		return 0
	default:
		return 90
	}
}