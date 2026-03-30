package main

import (
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/go-pdf/fpdf"
)

// sanitizePDF replaces all non-Latin1 characters that fpdf cannot handle.
// fpdf only supports characters 0-255. Any rune > 255 causes index-out-of-range panic.
func sanitizePDF(s string) string {
	replacements := map[string]string{
		"\u2022": "-",  // • bullet
		"\u2023": ">",  // ‣ triangular bullet
		"\u2043": "-",  // ⁃ hyphen bullet
		"\u25cf": "*",  // ● black circle
		"\u25cb": "o",  // ○ white circle
		"\u25a0": "#",  // ■ black square
		"\u25a1": "[]", // □ white square
		"\u2713": "[Y]",  // ✓ check mark
		"\u2717": "[X]",  // ✗ ballot x
		"\u2714": "[Y]",  // ✔ heavy check
		"\u2718": "[X]",  // ✘ heavy ballot x
		"\u274c": "[X]",  // ❌ cross mark
		"\u2705": "[Y]",  // ✅ white check
		"\u26a0": "[!]",  // ⚠ warning
		"\u2192": "->",   // → right arrow
		"\u2190": "<-",   // ← left arrow
		"\u2191": "^",    // ↑ up arrow
		"\u2193": "v",    // ↓ down arrow
		"\u21d2": "=>",   // ⇒ double right arrow
		"\u2605": "*",    // ★ star
		"\u2606": "*",    // ☆ white star
		"\u2610": "[ ]",  // ☐ ballot box
		"\u2611": "[Y]",  // ☑ ballot box checked
		"\u2612": "[X]",  // ☒ ballot box with x
		"\u2013": "-",    // – en dash
		"\u2014": "--",   // — em dash
		"\u2018": "'",    // ' left single quote
		"\u2019": "'",    // ' right single quote
		"\u201c": "\"",   // " left double quote
		"\u201d": "\"",   // " right double quote
		"\u2026": "...",  // … ellipsis
		"\u00a0": " ",    // non-breaking space
		"\u2265": ">=",   // ≥
		"\u2264": "<=",   // ≤
		"\u2260": "!=",   // ≠
		"\u00d7": "x",    // × multiplication
		"\u00f7": "/",    // ÷ division
		"\u00b1": "+/-",  // ± plus-minus
		"\u221e": "inf",  // ∞ infinity
		"\u00b0": " deg", // ° degree
		"\u00ae": "(R)",  // ® registered
		"\u00a9": "(C)",  // © copyright
		"\u2122": "(TM)", // ™ trademark
		"\u2550": "=",    // ═ box drawing double horizontal
		"\u2500": "-",    // ─ box drawing horizontal
		"\u2502": "|",    // │ box drawing vertical
		"\u251c": "|",    // ├ box drawing
		"\u2514": "`",    // └ box drawing
		"\u2554": "+",    // ╔ box drawing
		"\u2557": "+",    // ╗ box drawing
		"\u255a": "+",    // ╚ box drawing
		"\u255d": "+",    // ╝ box drawing
		"\u2551": "|",    // ║ box drawing double vertical
		"\u25b6": ">",    // ▶ right triangle
		"\u25c0": "<",    // ◀ left triangle
		"\u25b2": "^",    // ▲ up triangle
		"\u25bc": "v",    // ▼ down triangle
		"\u25c6": "*",    // ◆ diamond
		"\u25c7": "*",    // ◇ white diamond
		"\u26d3": "[CHAIN]", // ⛓ chain
	}

	// Also handle emoji (multi-byte sequences)
	emojiReplacements := map[string]string{
		"\U0001f534": "[!]",    // 🔴 red circle
		"\U0001f7e1": "[~]",    // 🟡 yellow circle
		"\U0001f7e2": "[OK]",   // 🟢 green circle
		"\U0001f512": "[LOCK]", // 🔒 lock
		"\U0001f513": "[OPEN]", // 🔓 open lock
		"\U0001f4ca": "[CHART]",// 📊 chart
		"\U0001f4cb": "[LIST]", // 📋 clipboard
		"\U0001f4dc": "[DOC]",  // 📜 scroll
		"\U0001f52c": "[SCAN]", // 🔬 microscope
	}

	result := s
	for k, v := range emojiReplacements {
		result = strings.ReplaceAll(result, k, v)
	}
	for k, v := range replacements {
		result = strings.ReplaceAll(result, k, v)
	}

	// Final pass: strip any remaining non-Latin1 characters
	var cleaned strings.Builder
	cleaned.Grow(len(result))
	for _, r := range result {
		if r <= 0xFF {
			cleaned.WriteRune(r)
		} else if unicode.IsPrint(r) {
			cleaned.WriteRune('?')
		}
		// silently drop non-printable non-Latin1
	}

	return cleaned.String()
}

// pdfSplitText is a safe wrapper around pdf.SplitText
func pdfSplitText(pdf *fpdf.Fpdf, text string, width float64) []string {
	return pdf.SplitText(sanitizePDF(text), width)
}

// pdfCell is a safe wrapper around pdf.CellFormat
func pdfCell(pdf *fpdf.Fpdf, w, h float64, text, border string, ln int, align string, fill bool) {
	pdf.CellFormat(w, h, sanitizePDF(text), border, ln, align, fill, 0, "")
}

// pdfMultiCell is a safe wrapper around pdf.MultiCell
func pdfMultiCell(pdf *fpdf.Fpdf, w, h float64, text, border, align string, fill bool) {
	pdf.MultiCell(w, h, sanitizePDF(text), border, align, fill)
}

// AuditReportData holds all data for the CISO audit report
type AuditReportData struct {
	CompanyName    string
	Target         string
	ScanTime       string
	RiskScore      float64
	RiskLevel      string
	TotalEndpoints int
	Vulnerable     int
	Critical       int
	Safe           int
	Findings       []ScanResult
	KillList       []KillListItem
	MigrationSteps []MigrationStep
	CipherEnum     *CipherEnumResult
	CertChain      *CertChainResult
}

type KillListItem struct {
	Priority int
	What     string
	Where    string
	Risk     string
	Action   string
	Deadline string
}

type MigrationStep struct {
	Phase       string
	Title       string
	Description string
	Timeline    string
	Impact      string
}

// GenerateAuditReport creates a CISO-ready audit PDF
func GenerateAuditReport(target string, results []ScanResult, cipherEnum *CipherEnumResult, certChain *CertChainResult, outputFile string) error {
	data := buildAuditData(target, results, cipherEnum, certChain)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// Set font immediately — this initializes the character width table
	pdf.SetFont("Helvetica", "", 10)

	// Cover page
	addAuditCoverPage(pdf, data)

	// Executive summary
	addAuditExecutiveSummary(pdf, data)

	// Kill list
	addAuditKillList(pdf, data)

	// CBOM summary
	addAuditCBOMSummary(pdf, data)

	// Migration roadmap
	addAuditMigrationRoadmap(pdf, data)

	// Detailed findings
	addAuditDetailedFindings(pdf, data)

	// Compliance attestation
	addAuditCompliance(pdf, data)

	err := pdf.OutputFileAndClose(outputFile)
	if err != nil {
		return fmt.Errorf("failed to write audit PDF: %w", err)
	}

	fmt.Printf("  Audit report written to: %s\n", outputFile)
	return nil
}

func buildAuditData(target string, results []ScanResult, cipherEnum *CipherEnumResult, certChain *CertChainResult) AuditReportData {
	critical, safe := 0, 0
	for _, r := range results {
		if strings.Contains(r.RiskLevel, "CRITICAL") {
			critical++
		} else if r.RiskLevel == "SAFE" {
			safe++
		}
	}

	total := len(results)
	vulnerable := total - safe
	pct := 0.0
	if total > 0 {
		pct = float64(vulnerable) / float64(total) * 100
	}

	riskLevel := "CRITICAL"
	if pct == 0 {
		riskLevel = "SAFE"
	} else if pct < 30 {
		riskLevel = "LOW"
	} else if pct < 70 {
		riskLevel = "MODERATE"
	}

	// Build kill list
	killList := buildKillList(results, cipherEnum, certChain)

	// Build migration steps
	migrationSteps := buildMigrationSteps(results, cipherEnum)

	return AuditReportData{
		CompanyName:    extractCompanyName(target),
		Target:         target,
		ScanTime:       time.Now().Format("2006-01-02 15:04:05 MST"),
		RiskScore:      pct,
		RiskLevel:      riskLevel,
		TotalEndpoints: total,
		Vulnerable:     vulnerable,
		Critical:       critical,
		Safe:           safe,
		Findings:       results,
		KillList:       killList,
		MigrationSteps: migrationSteps,
		CipherEnum:     cipherEnum,
		CertChain:      certChain,
	}
}

func buildKillList(results []ScanResult, cipherEnum *CipherEnumResult, certChain *CertChainResult) []KillListItem {
	var items []KillListItem
	priority := 1

	// Check TLS versions from cipher enumeration
	if cipherEnum != nil {
		for _, v := range cipherEnum.SupportedVersions {
			if v.Supported && (strings.Contains(v.Name, "1.0") || strings.Contains(v.Name, "1.1") || strings.Contains(v.Name, "SSL")) {
				items = append(items, KillListItem{
					Priority: priority,
					What:     fmt.Sprintf("%s Protocol", v.Name),
					Where:    fmt.Sprintf("%s:%d", cipherEnum.Host, cipherEnum.Port),
					Risk:     "HIGH -- Deprecated protocol with known vulnerabilities",
					Action:   fmt.Sprintf("Disable %s in server configuration", v.Name),
					Deadline: "Immediate",
				})
				priority++
			}
		}

		// Check for weak ciphers
		for _, c := range cipherEnum.SupportedCiphers {
			if c.Supported && isWeakCipher(c.Name) {
				items = append(items, KillListItem{
					Priority: priority,
					What:     fmt.Sprintf("Weak cipher: %s", c.Name),
					Where:    fmt.Sprintf("%s:%d", cipherEnum.Host, cipherEnum.Port),
					Risk:     "HIGH -- Classically broken cipher suite",
					Action:   "Remove from server cipher suite configuration",
					Deadline: "Immediate",
				})
				priority++
			}
		}

		// Check cipher preference
		if !cipherEnum.PrefersCipherOrder {
			items = append(items, KillListItem{
				Priority: priority,
				What:     "Client cipher preference enabled",
				Where:    fmt.Sprintf("%s:%d", cipherEnum.Host, cipherEnum.Port),
				Risk:     "MEDIUM -- Attacker can force weaker cipher",
				Action:   "Configure server to enforce its own cipher order",
				Deadline: "Within 30 days",
			})
			priority++
		}
	}

	// Check certificate chain
	if certChain != nil {
		for _, cert := range certChain.Certificates {
			if cert.OverallRisk == "CRITICAL" {
				items = append(items, KillListItem{
					Priority: priority,
					What:     fmt.Sprintf("%s certificate: %s (%s)", cert.Position, cert.CommonName, cert.KeyAlgorithm),
					Where:    fmt.Sprintf("%s:%d", certChain.Host, certChain.Port),
					Risk:     "CRITICAL -- Broken by Shor's algorithm",
					Action:   fmt.Sprintf("Replace %s key with ML-DSA or hybrid certificate", cert.KeyAlgorithm),
					Deadline: "Before CNSA 2.0 (2033)",
				})
				priority++
			}
		}
	}

	// Check quantum-vulnerable endpoints
	for _, r := range results {
		if strings.Contains(r.RiskLevel, "CRITICAL") {
			items = append(items, KillListItem{
				Priority: priority,
				What:     fmt.Sprintf("Quantum-vulnerable key exchange: %s", r.KeyExchange),
				Where:    fmt.Sprintf("%s:%d (%s)", r.Host, r.Port, r.Service),
				Risk:     "CRITICAL -- Key exchange broken by Shor's algorithm",
				Action:   r.Remediation,
				Deadline: "Before CNSA 2.0 (2033)",
			})
			priority++
		}
	}

	// Sort by priority
	sort.Slice(items, func(i, j int) bool {
		return items[i].Priority < items[j].Priority
	})

	return items
}

func buildMigrationSteps(results []ScanResult, cipherEnum *CipherEnumResult) []MigrationStep {
	steps := []MigrationStep{
		{
			Phase:       "Phase 1",
			Title:       "Disable Legacy Protocols (Immediate)",
			Description: "Disable TLS 1.0, TLS 1.1, and SSL 3.0 on all servers. These are deprecated and have known classical vulnerabilities. This is a configuration change with no application impact for modern clients.",
			Timeline:    "1-2 weeks",
			Impact:      "Eliminates classical downgrade attacks. May affect very old clients (IE 6, Android 4.x).",
		},
		{
			Phase:       "Phase 2",
			Title:       "Enable PQC Key Exchange (Short-term)",
			Description: "Update TLS libraries (OpenSSL 3.5+, BoringSSL) and enable X25519+ML-KEM-768 hybrid key exchange. This protects new connections against HNDL attacks while maintaining backward compatibility.",
			Timeline:    "1-3 months",
			Impact:      "New TLS connections become quantum-safe. No impact on existing functionality. Hybrid mode ensures backward compatibility.",
		},
		{
			Phase:       "Phase 3",
			Title:       "Enforce Server Cipher Preference (Short-term)",
			Description: "Configure all TLS endpoints to enforce server cipher order preference. Remove weak cipher suites (3DES, RC4, CBC+SHA1). Prioritize AES-256-GCM and ChaCha20-Poly1305.",
			Timeline:    "2-4 weeks",
			Impact:      "Prevents cipher downgrade attacks. Improves overall TLS security posture.",
		},
		{
			Phase:       "Phase 4",
			Title:       "Migrate Certificate Chain (Medium-term)",
			Description: "Work with Certificate Authorities to obtain hybrid (classical + PQC) certificates using ML-DSA or composite signatures. Deploy in staging first, then production. Root and intermediate CA migration requires coordination with CA vendors.",
			Timeline:    "3-12 months",
			Impact:      "Certificate-based authentication becomes quantum-safe. Requires CA support for PQC certificates.",
		},
		{
			Phase:       "Phase 5",
			Title:       "SSH and Email Migration (Medium-term)",
			Description: "Upgrade SSH servers to OpenSSH 9.x+ and enable sntrup761x25519 hybrid key exchange. Upgrade SMTP/IMAP to support PQC STARTTLS. Rotate all SSH host keys to PQC-safe algorithms.",
			Timeline:    "3-6 months",
			Impact:      "Remote access and email infrastructure become quantum-safe.",
		},
		{
			Phase:       "Phase 6",
			Title:       "Full Architecture Audit (Long-term)",
			Description: "Audit internal infrastructure: VPNs (IPSec), databases, key management systems, code signing, S/MIME, disk encryption. Implement crypto agility for future algorithm transitions. Establish continuous monitoring.",
			Timeline:    "6-18 months",
			Impact:      "Complete quantum-safe posture across all cryptographic touchpoints.",
		},
	}

	return steps
}

func extractCompanyName(target string) string {
	parts := strings.Split(target, ".")
	if len(parts) >= 2 {
		name := parts[len(parts)-2]
		if len(name) > 0 {
			return strings.ToUpper(name[:1]) + name[1:]
		}
		return name
	}
	return target
}

// ==========================================
// COVER PAGE
// ==========================================

func addAuditCoverPage(pdf *fpdf.Fpdf, data AuditReportData) {
	pdf.AddPage()

	// Purple gradient header
	pdf.SetFillColor(139, 92, 246)
	pdf.Rect(0, 0, 210, 297, "F")

	// Darker overlay at bottom
	pdf.SetFillColor(15, 23, 42)
	pdf.Rect(0, 180, 210, 117, "F")

	// Title
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetXY(20, 30)
	pdfCell(pdf, 170, 8, "CONFIDENTIAL", "", 1, "L", false)

	pdf.SetFont("Helvetica", "B", 36)
	pdf.SetXY(20, 60)
	pdfCell(pdf, 170, 18, "Post-Quantum", "", 1, "L", false)
	pdf.SetXY(20, 80)
	pdfCell(pdf, 170, 18, "Security Audit", "", 1, "L", false)

	pdf.SetFont("Helvetica", "", 16)
	pdf.SetXY(20, 110)
	pdfCell(pdf, 170, 10, fmt.Sprintf("Prepared for: %s", data.CompanyName), "", 1, "L", false)

	pdf.SetFont("Helvetica", "", 12)
	pdf.SetXY(20, 125)
	pdfCell(pdf, 170, 8, fmt.Sprintf("Target: %s", data.Target), "", 1, "L", false)
	pdf.SetXY(20, 135)
	pdfCell(pdf, 170, 8, fmt.Sprintf("Date: %s", data.ScanTime), "", 1, "L", false)

	// Risk score on cover
	scoreColor := getRiskColor(data.RiskLevel)
	pdf.SetFillColor(scoreColor.R, scoreColor.G, scoreColor.B)
	pdf.RoundedRect(20, 155, 50, 20, 4, "1234", "F")
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetXY(20, 158)
	pdfCell(pdf, 50, 14, fmt.Sprintf("Score: %.0f", data.RiskScore), "", 0, "C", false)

	// Bottom section
	pdf.SetTextColor(148, 163, 184)
	pdf.SetFont("Helvetica", "", 10)
	pdf.SetXY(20, 200)
	pdfCell(pdf, 170, 6, "This report contains:", "", 1, "L", false)

	items := []string{
		"1. Executive Summary & Quantum Risk Score",
		"2. Priority Kill List -- Immediate Actions Required",
		"3. Cryptographic Bill of Materials (CBOM)",
		"4. Migration Roadmap to Post-Quantum Cryptography",
		"5. Detailed Technical Findings",
		"6. CNSA 2.0 Compliance Assessment",
	}

	pdf.SetFont("Helvetica", "", 9)
	for _, item := range items {
		pdf.SetXY(25, pdf.GetY()+1)
		pdfCell(pdf, 165, 5, item, "", 1, "L", false)
	}

	// Footer
	pdf.SetTextColor(100, 116, 139)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(20, 270)
	pdfCell(pdf, 170, 5, "Generated by PQScan v0.1.0 -- Post-Quantum Cryptography Vulnerability Scanner", "", 1, "L", false)
	pdf.SetXY(20, 276)
	pdfCell(pdf, 170, 5, "https://github.com/Hacker21-punk/pqscan", "", 1, "L", false)
}

// ==========================================
// EXECUTIVE SUMMARY
// ==========================================

func addAuditExecutiveSummary(pdf *fpdf.Fpdf, data AuditReportData) {
	pdf.AddPage()
	addAuditPageHeader(pdf, "Executive Summary")

	y := 35.0

	// Risk score card
	scoreColor := getRiskColor(data.RiskLevel)
	pdf.SetFillColor(scoreColor.R, scoreColor.G, scoreColor.B)
	pdf.RoundedRect(15, y, 55, 40, 4, "1234", "F")

	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 32)
	pdf.SetXY(15, y+5)
	pdfCell(pdf, 55, 15, fmt.Sprintf("%.0f", data.RiskScore), "", 1, "C", false)
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetXY(15, y+22)
	pdfCell(pdf, 55, 5, "Quantum Risk Score", "", 1, "C", false)
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetXY(15, y+28)
	pdfCell(pdf, 55, 8, data.RiskLevel, "", 1, "C", false)

	// Key metrics
	pdf.SetTextColor(31, 41, 55)
	pdf.SetFont("Helvetica", "", 10)

	metricsX := 80.0
	metrics := []struct{ label, value string }{
		{"Total Endpoints Scanned", fmt.Sprintf("%d", data.TotalEndpoints)},
		{"Quantum-Vulnerable", fmt.Sprintf("%d (%.0f%%)", data.Vulnerable, data.RiskScore)},
		{"Critical Findings", fmt.Sprintf("%d", data.Critical)},
		{"Quantum-Safe Endpoints", fmt.Sprintf("%d", data.Safe)},
		{"Priority Actions Required", fmt.Sprintf("%d", len(data.KillList))},
		{"Estimated Migration Time", estimateMigrationTime(data.Critical)},
	}

	for i, m := range metrics {
		my := y + float64(i)*7
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(100, 116, 139)
		pdf.SetXY(metricsX, my)
		pdfCell(pdf, 60, 6, m.label, "", 0, "L", false)
		pdf.SetFont("Helvetica", "B", 9)
		pdf.SetTextColor(31, 41, 55)
		pdfCell(pdf, 55, 6, m.value, "", 1, "R", false)
	}

	// Key findings narrative
	y = 85.0
	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(31, 41, 55)
	pdf.SetXY(15, y)
	pdfCell(pdf, 180, 7, "Key Findings", "", 1, "L", false)
	y += 10

	findings := []string{
		fmt.Sprintf("- %d of %d endpoints (%.0f%%) use encryption algorithms that will be completely broken by quantum computers running Shor's algorithm.", data.Vulnerable, data.TotalEndpoints, data.RiskScore),
		"- All RSA, ECDSA, ECDH, and Diffie-Hellman based cryptography is vulnerable. An attacker with a cryptographically-relevant quantum computer could recover private keys, decrypt all traffic, and forge digital signatures.",
		"- Harvest Now, Decrypt Later (HNDL) risk is ACTIVE. Data encrypted today with quantum-vulnerable algorithms may already be captured for future decryption.",
	}

	if data.CipherEnum != nil && data.CipherEnum.HasPQCSupport {
		findings = append(findings,
			fmt.Sprintf("- Post-quantum key exchange (%s) was detected. However, certificate chains and legacy protocol support still present quantum risk.", data.CipherEnum.PQCDetails))
	}

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(31, 41, 55)
	for _, f := range findings {
		pdf.SetXY(15, y)
		lines := pdfSplitText(pdf, f, 175)
		for _, line := range lines {
			pdf.SetX(15)
			pdfCell(pdf, 175, 5, line, "", 1, "L", false)
		}
		y = pdf.GetY() + 3
	}

	addAuditFooter(pdf, data)
}

// ==========================================
// KILL LIST
// ==========================================

func addAuditKillList(pdf *fpdf.Fpdf, data AuditReportData) {
	pdf.AddPage()
	addAuditPageHeader(pdf, "Priority Kill List -- Immediate Actions")

	y := 35.0

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(100, 116, 139)
	pdf.SetXY(15, y)
	pdfCell(pdf, 180, 5, "The following items must be addressed in order of priority to reduce quantum risk.", "", 1, "L", false)
	y += 10

	// Table header
	pdf.SetFillColor(31, 41, 55)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetXY(15, y)
	pdf.CellFormat(10, 7, "#", "1", 0, "C", true, 0, "")
	pdf.CellFormat(55, 7, "Issue", "1", 0, "L", true, 0, "")
	pdf.CellFormat(35, 7, "Location", "1", 0, "L", true, 0, "")
	pdf.CellFormat(50, 7, "Action", "1", 0, "L", true, 0, "")
	pdf.CellFormat(30, 7, "Deadline", "1", 1, "C", true, 0, "")
	y += 7

	pdf.SetFont("Helvetica", "", 7)
	for i, item := range data.KillList {
		if y+12 > 270 {
			addAuditFooter(pdf, data)
			pdf.AddPage()
			addAuditPageHeader(pdf, "Priority Kill List (continued)")
			y = 35.0
		}

		if i%2 == 0 {
			pdf.SetFillColor(243, 244, 246)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}

		pdf.SetTextColor(31, 41, 55)
		pdf.SetXY(15, y)
		pdf.CellFormat(10, 10, fmt.Sprintf("%d", item.Priority), "1", 0, "C", true, 0, "")

		// Truncate long text and sanitize
		what := sanitizePDF(item.What)
		if len(what) > 35 {
			what = what[:32] + "..."
		}
		pdf.CellFormat(55, 10, what, "1", 0, "L", true, 0, "")

		where := sanitizePDF(item.Where)
		if len(where) > 22 {
			where = where[:19] + "..."
		}
		pdf.CellFormat(35, 10, where, "1", 0, "L", true, 0, "")

		action := sanitizePDF(item.Action)
		if len(action) > 32 {
			action = action[:29] + "..."
		}
		pdf.CellFormat(50, 10, action, "1", 0, "L", true, 0, "")
		pdf.CellFormat(30, 10, sanitizePDF(item.Deadline), "1", 1, "C", true, 0, "")
		y += 10
	}

	addAuditFooter(pdf, data)
}

// ==========================================
// CBOM SUMMARY
// ==========================================

func addAuditCBOMSummary(pdf *fpdf.Fpdf, data AuditReportData) {
	pdf.AddPage()
	addAuditPageHeader(pdf, "Cryptographic Bill of Materials (CBOM)")

	y := 35.0

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(100, 116, 139)
	pdf.SetXY(15, y)
	cbomDesc := fmt.Sprintf("The following is a summary of all cryptographic assets discovered during the scan. A machine-readable CycloneDX v1.6 CBOM can be generated using: pqscan --format cbom -o cbom.json %s", data.Target)
	lines := pdfSplitText(pdf, cbomDesc, 175)
	for _, line := range lines {
		pdf.SetX(15)
		pdfCell(pdf, 175, 5, line, "", 1, "L", false)
	}
	y = pdf.GetY() + 8

	// Findings table
	pdf.SetFillColor(31, 41, 55)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetXY(15, y)
	pdf.CellFormat(40, 7, "Endpoint", "1", 0, "L", true, 0, "")
	pdf.CellFormat(20, 7, "Service", "1", 0, "C", true, 0, "")
	pdf.CellFormat(20, 7, "Protocol", "1", 0, "C", true, 0, "")
	pdf.CellFormat(50, 7, "Cipher Suite", "1", 0, "L", true, 0, "")
	pdf.CellFormat(30, 7, "Cert Key", "1", 0, "C", true, 0, "")
	pdf.CellFormat(20, 7, "Risk", "1", 1, "C", true, 0, "")
	y += 7

	pdf.SetFont("Helvetica", "", 7)
	for i, r := range data.Findings {
		if y+8 > 270 {
			addAuditFooter(pdf, data)
			pdf.AddPage()
			addAuditPageHeader(pdf, "CBOM (continued)")
			y = 35.0
		}

		if i%2 == 0 {
			pdf.SetFillColor(243, 244, 246)
		} else {
			pdf.SetFillColor(255, 255, 255)
		}

		endpoint := fmt.Sprintf("%s:%d", r.Host, r.Port)
		cipher := sanitizePDF(r.CipherSuite)
		if len(cipher) > 32 {
			cipher = cipher[:29] + "..."
		}
		certKey := ""
		if r.Certificate.Subject != "" {
			certKey = sanitizePDF(r.Certificate.KeyAlgorithm)
		}

		pdf.SetXY(15, y)
		pdf.SetTextColor(31, 41, 55)
		pdf.CellFormat(40, 7, sanitizePDF(endpoint), "1", 0, "L", true, 0, "")
		pdf.CellFormat(20, 7, sanitizePDF(r.Service), "1", 0, "C", true, 0, "")
		pdf.CellFormat(20, 7, sanitizePDF(r.Protocol), "1", 0, "C", true, 0, "")
		pdf.CellFormat(50, 7, cipher, "1", 0, "L", true, 0, "")
		pdf.CellFormat(30, 7, certKey, "1", 0, "C", true, 0, "")

		riskText := "CRITICAL"
		if r.RiskLevel == "SAFE" {
			riskText = "SAFE"
		}
		pdf.CellFormat(20, 7, riskText, "1", 1, "C", true, 0, "")
		y += 7
	}

	addAuditFooter(pdf, data)
}

// ==========================================
// MIGRATION ROADMAP
// ==========================================

func addAuditMigrationRoadmap(pdf *fpdf.Fpdf, data AuditReportData) {
	pdf.AddPage()
	addAuditPageHeader(pdf, "Migration Roadmap to Post-Quantum Cryptography")

	y := 35.0

	for _, step := range data.MigrationSteps {
		if y+35 > 260 {
			addAuditFooter(pdf, data)
			pdf.AddPage()
			addAuditPageHeader(pdf, "Migration Roadmap (continued)")
			y = 35.0
		}

		// Phase badge
		pdf.SetFillColor(139, 92, 246)
		pdf.SetTextColor(255, 255, 255)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.RoundedRect(15, y, 20, 6, 2, "1234", "F")
		pdf.SetXY(15, y)
		pdfCell(pdf, 20, 6, step.Phase, "", 0, "C", false)

		// Timeline badge
		pdf.SetFillColor(59, 130, 246)
		timelineText := sanitizePDF(step.Timeline)
		badgeWidth := float64(len(timelineText)*2 + 10)
		if badgeWidth < 25 {
			badgeWidth = 25
		}
		pdf.RoundedRect(195-badgeWidth, y, badgeWidth, 6, 2, "1234", "F")
		pdf.SetXY(195-badgeWidth, y)
		pdfCell(pdf, badgeWidth, 6, timelineText, "", 0, "C", false)

		// Title
		pdf.SetTextColor(31, 41, 55)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetXY(40, y)
		pdfCell(pdf, 110, 6, step.Title, "", 1, "L", false)
		y += 9

		// Description
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(75, 85, 99)
		pdf.SetXY(40, y)
		descLines := pdfSplitText(pdf, step.Description, 150)
		for _, line := range descLines {
			pdf.SetX(40)
			pdfCell(pdf, 150, 4, line, "", 1, "L", false)
		}
		y = pdf.GetY() + 2

		// Impact
		pdf.SetFont("Helvetica", "I", 7)
		pdf.SetTextColor(100, 116, 139)
		pdf.SetXY(40, y)
		impactLines := pdfSplitText(pdf, "Impact: "+step.Impact, 150)
		for _, line := range impactLines {
			pdf.SetX(40)
			pdfCell(pdf, 150, 4, line, "", 1, "L", false)
		}

		y = pdf.GetY() + 6
	}

	addAuditFooter(pdf, data)
}

// ==========================================
// DETAILED FINDINGS
// ==========================================

func addAuditDetailedFindings(pdf *fpdf.Fpdf, data AuditReportData) {
	pdf.AddPage()
	addAuditPageHeader(pdf, "Detailed Technical Findings")

	y := 35.0

	// Cipher enumeration results
	if data.CipherEnum != nil {
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(31, 41, 55)
		pdf.SetXY(15, y)
		pdfCell(pdf, 180, 7, "TLS Version Support", "", 1, "L", false)
		y += 9

		pdf.SetFont("Helvetica", "", 8)
		for _, v := range data.CipherEnum.SupportedVersions {
			status := "Disabled"
			if v.Supported {
				status = "ENABLED"
			}
			pdf.SetXY(20, y)
			pdf.SetTextColor(31, 41, 55)
			pdfCell(pdf, 30, 5, v.Name, "", 0, "L", false)
			if v.Supported && (strings.Contains(v.Name, "1.0") || strings.Contains(v.Name, "1.1") || strings.Contains(v.Name, "SSL")) {
				pdf.SetTextColor(220, 38, 38)
			} else if v.Supported {
				pdf.SetTextColor(22, 163, 74)
			} else {
				pdf.SetTextColor(100, 116, 139)
			}
			pdfCell(pdf, 30, 5, status, "", 1, "L", false)
			y += 5
		}

		y += 5
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(31, 41, 55)
		pdf.SetXY(15, y)
		pdfCell(pdf, 180, 7, "Key Exchange Groups", "", 1, "L", false)
		y += 9

		pdf.SetFont("Helvetica", "", 8)
		for _, c := range data.CipherEnum.SupportedCurves {
			pdf.SetXY(20, y)
			pdf.SetTextColor(31, 41, 55)
			pdfCell(pdf, 50, 5, c.Name, "", 0, "L", false)

			if c.Supported && c.IsPQC {
				pdf.SetTextColor(22, 163, 74)
				pdfCell(pdf, 30, 5, "SUPPORTED", "", 0, "L", false)
				pdfCell(pdf, 80, 5, "Post-Quantum Safe", "", 1, "L", false)
			} else if c.Supported {
				pdf.SetTextColor(220, 38, 38)
				pdfCell(pdf, 30, 5, "SUPPORTED", "", 0, "L", false)
				pdfCell(pdf, 80, 5, "Quantum-Vulnerable", "", 1, "L", false)
			} else {
				pdf.SetTextColor(100, 116, 139)
				pdfCell(pdf, 30, 5, "not supported", "", 1, "L", false)
			}
			y += 5
		}
	}

	// Certificate chain
	if data.CertChain != nil {
		y += 8
		if y > 240 {
			addAuditFooter(pdf, data)
			pdf.AddPage()
			addAuditPageHeader(pdf, "Certificate Chain Analysis")
			y = 35.0
		}

		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(31, 41, 55)
		pdf.SetXY(15, y)
		pdfCell(pdf, 180, 7, "Certificate Chain Analysis", "", 1, "L", false)
		y += 9

		pdf.SetFont("Helvetica", "", 8)
		for _, cert := range data.CertChain.Certificates {
			if y+15 > 270 {
				addAuditFooter(pdf, data)
				pdf.AddPage()
				addAuditPageHeader(pdf, "Certificate Chain Analysis (continued)")
				y = 35.0
			}

			pdf.SetXY(20, y)
			pdf.SetTextColor(31, 41, 55)
			pdf.SetFont("Helvetica", "B", 8)
			pdfCell(pdf, 180, 5, fmt.Sprintf("%s: %s", sanitizePDF(cert.Position), sanitizePDF(cert.CommonName)), "", 1, "L", false)
			y += 5

			pdf.SetFont("Helvetica", "", 7)
			pdf.SetTextColor(75, 85, 99)

			keyInfo := sanitizePDF(cert.KeyAlgorithm)
			if cert.KeySize > 0 {
				keyInfo = fmt.Sprintf("%s (%d-bit)", keyInfo, cert.KeySize)
			}

			pdf.SetXY(25, y)
			certLine := fmt.Sprintf("Key: %s | Signature: %s | Risk: %s", keyInfo, sanitizePDF(cert.SignatureAlg), sanitizePDF(cert.OverallRisk))
			pdfCell(pdf, 180, 4, certLine, "", 1, "L", false)
			y += 6
		}
	}

	addAuditFooter(pdf, data)
}

// ==========================================
// COMPLIANCE PAGE
// ==========================================

func addAuditCompliance(pdf *fpdf.Fpdf, data AuditReportData) {
	pdf.AddPage()
	addAuditPageHeader(pdf, "CNSA 2.0 Compliance Assessment")

	y := 35.0

	// Compliance table
	milestones := []struct {
		year string
		req  string
	}{
		{"2025", "Prefer PQC for new systems"},
		{"2027", "New systems MUST use PQC"},
		{"2030", "Legacy symmetric crypto must be upgraded"},
		{"2033", "All protocols must be quantum-safe"},
		{"2035", "Complete migration -- no exceptions"},
	}

	status := "FAILING"
	if data.Critical == 0 {
		status = "PASSING"
	}

	pdf.SetFillColor(31, 41, 55)
	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetXY(15, y)
	pdf.CellFormat(25, 7, "Year", "1", 0, "C", true, 0, "")
	pdf.CellFormat(110, 7, "Requirement", "1", 0, "L", true, 0, "")
	pdf.CellFormat(45, 7, "Status", "1", 1, "C", true, 0, "")
	y += 7

	pdf.SetFont("Helvetica", "", 9)
	for _, m := range milestones {
		pdf.SetXY(15, y)
		pdf.SetTextColor(31, 41, 55)
		pdf.SetFillColor(243, 244, 246)
		pdf.CellFormat(25, 8, m.year, "1", 0, "C", true, 0, "")
		pdf.CellFormat(110, 8, sanitizePDF(m.req), "1", 0, "L", true, 0, "")

		if status == "PASSING" {
			pdf.SetTextColor(22, 163, 74)
			pdf.CellFormat(45, 8, "PASSING", "1", 1, "C", true, 0, "")
		} else {
			pdf.SetTextColor(220, 38, 38)
			pdf.CellFormat(45, 8, "FAILING", "1", 1, "C", true, 0, "")
		}
		y += 8
	}

	// Attestation box
	y += 15
	pdf.SetDrawColor(139, 92, 246)
	pdf.SetLineWidth(0.5)
	pdf.RoundedRect(15, y, 180, 50, 3, "1234", "D")

	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(31, 41, 55)
	pdf.SetXY(20, y+5)
	pdfCell(pdf, 170, 7, "Audit Attestation", "", 1, "L", false)

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(75, 85, 99)
	attestation := fmt.Sprintf("This report certifies that %s's public-facing infrastructure at %s was scanned for post-quantum cryptographic vulnerabilities on %s using PQScan v0.1.0. The scan identified %d endpoints, of which %d (%.0f%%) use quantum-vulnerable cryptographic algorithms. This assessment covers TLS, SSH, and STARTTLS protocols on externally-accessible endpoints only.",
		data.CompanyName, data.Target, data.ScanTime, data.TotalEndpoints, data.Vulnerable, data.RiskScore)

	pdf.SetXY(20, y+14)
	attLines := pdfSplitText(pdf, attestation, 165)
	for _, line := range attLines {
		pdf.SetX(20)
		pdfCell(pdf, 165, 5, line, "", 1, "L", false)
	}

	// Signature line
	y = pdf.GetY() + 15
	pdf.SetDrawColor(100, 116, 139)
	pdf.Line(20, y, 90, y)
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(100, 116, 139)
	pdf.SetXY(20, y+2)
	pdfCell(pdf, 70, 4, "Auditor Signature / Date", "", 0, "L", false)

	pdf.Line(110, y, 190, y)
	pdf.SetXY(110, y+2)
	pdfCell(pdf, 80, 4, "Organization Representative / Date", "", 0, "L", false)

	addAuditFooter(pdf, data)
}

// ==========================================
// HELPERS
// ==========================================

func addAuditPageHeader(pdf *fpdf.Fpdf, title string) {
	pdf.SetFillColor(139, 92, 246)
	pdf.Rect(0, 0, 210, 25, "F")

	pdf.SetTextColor(255, 255, 255)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetXY(15, 7)
	pdfCell(pdf, 130, 10, title, "", 0, "L", false)

	pdf.SetFont("Helvetica", "", 8)
	pdf.SetXY(145, 9)
	pdfCell(pdf, 50, 8, "PQScan Audit Report", "", 0, "R", false)
}

func addAuditFooter(pdf *fpdf.Fpdf, data AuditReportData) {
	pdf.SetDrawColor(100, 116, 139)
	pdf.SetLineWidth(0.3)
	pdf.Line(15, 280, 195, 280)

	pdf.SetTextColor(100, 116, 139)
	pdf.SetFont("Helvetica", "", 7)
	pdf.SetXY(15, 282)
	pdfCell(pdf, 60, 4, "CONFIDENTIAL", "", 0, "L", false)
	pdfCell(pdf, 60, 4, fmt.Sprintf("Target: %s", data.Target), "", 0, "C", false)
	pdfCell(pdf, 60, 4, fmt.Sprintf("Page %d | PQScan v0.1.0", pdf.PageNo()), "", 0, "R", false)
}

func estimateMigrationTime(critical int) string {
	if critical == 0 {
		return "None needed"
	} else if critical < 5 {
		return "2-4 weeks"
	} else if critical < 20 {
		return "1-3 months"
	}
	return "6-18 months"
}