package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/go-pdf/fpdf"
)

// PDF color definitions
type pdfColor struct {
	R, G, B int
}

var (
	colorCritical  = pdfColor{220, 38, 38}
	colorHigh      = pdfColor{234, 88, 12}
	colorModerate  = pdfColor{202, 138, 4}
	colorSafe      = pdfColor{22, 163, 74}
	colorBlue      = pdfColor{59, 130, 246}
	colorPurple    = pdfColor{139, 92, 246}
	colorDarkBg    = pdfColor{15, 23, 42}
	colorCardBg    = pdfColor{30, 41, 59}
	colorText      = pdfColor{241, 245, 249}
	colorTextDim   = pdfColor{148, 163, 184}
	colorTextMuted = pdfColor{100, 116, 139}
	colorBorder    = pdfColor{51, 65, 85}
	colorWhite     = pdfColor{255, 255, 255}
	colorBlack     = pdfColor{0, 0, 0}
	colorLightGray = pdfColor{243, 244, 246}
	colorMedGray   = pdfColor{156, 163, 175}
	colorDarkText  = pdfColor{31, 41, 55}
)

// GeneratePDFReport creates a professional PDF report
func GeneratePDFReport(target string, results []ScanResult, outputFile string) error {
	data := buildPDFData(target, results)

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetAutoPageBreak(true, 20)

	// Page 1: Executive Summary
	addExecutiveSummary(pdf, data)

	// Page 2: Risk Breakdown
	addRiskBreakdown(pdf, data)

	// Page 3+: Detailed Findings
	addDetailedFindings(pdf, data)

	// Last Page: Recommendations
	addRecommendations(pdf, data)

	err := pdf.OutputFileAndClose(outputFile)
	if err != nil {
		return fmt.Errorf("failed to write PDF: %w", err)
	}

	fmt.Printf("  PDF report written to: %s\n", outputFile)
	return nil
}

// PDF report data structure
type PDFData struct {
	Target          string
	ScanTime        string
	TotalEndpoints  int
	Vulnerable      int
	Critical        int
	High            int
	Moderate        int
	Safe            int
	RiskScore       float64
	RiskLevel       string
	VulnerablePct   float64
	CNSAStatus      string
	HNDLRisk        string
	MigrationWeeks  string
	Findings        []PDFFinding
	Services        map[string]int
	ServiceRisks    map[string]string
}

type PDFFinding struct {
	Host          string
	Port          int
	Service       string
	Protocol      string
	CipherSuite   string
	KeyExchange   string
	RiskLevel     string
	QuantumThreat string
	Remediation   string
	CertSubject   string
	CertKeyAlg    string
	CertKeySize   int
	CertSigAlg    string
	CertExpiry    string
	CertRisk      string
	HasCert       bool
	Error         string
}

func buildPDFData(target string, results []ScanResult) PDFData {
	critical, high, moderate, safe := 0, 0, 0, 0

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
			critical++
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
	} else if pct < 90 {
		riskLevel = "HIGH"
	}

	// Service breakdown
	services := make(map[string]int)
	serviceRisks := make(map[string]string)
	for _, r := range results {
		services[r.Service]++
		if strings.Contains(r.RiskLevel, "CRITICAL") {
			serviceRisks[r.Service] = "CRITICAL"
		} else if _, exists := serviceRisks[r.Service]; !exists {
			serviceRisks[r.Service] = "SAFE"
		}
	}

	// Build findings
	var findings []PDFFinding
	for _, r := range results {
		f := PDFFinding{
			Host:          r.Host,
			Port:          r.Port,
			Service:       r.Service,
			Protocol:      r.Protocol,
			CipherSuite:   r.CipherSuite,
			KeyExchange:   r.KeyExchange,
			RiskLevel:     r.RiskLevel,
			QuantumThreat: r.QuantumThreat,
			Remediation:   r.Remediation,
			Error:         r.Error,
		}

		if r.Certificate.Subject != "" {
			f.HasCert = true
			f.CertSubject = r.Certificate.Subject
			f.CertKeyAlg = r.Certificate.KeyAlgorithm
			f.CertKeySize = r.Certificate.KeySize
			f.CertSigAlg = r.Certificate.SignatureAlg
			f.CertExpiry = r.Certificate.NotAfter.Format("2006-01-02")
			f.CertRisk = classifyCertRisk(r.Certificate.KeyAlgorithm)
		}

		findings = append(findings, f)
	}

	// Migration estimate
	migrationWeeks := "1-2 weeks"
	if critical > 20 {
		migrationWeeks = "6-18 months"
	} else if critical > 5 {
		migrationWeeks = "1-3 months"
	} else if critical > 0 {
		migrationWeeks = "2-4 weeks"
	} else {
		migrationWeeks = "None needed"
	}

	cnsaStatus := "FAILING"
	if critical == 0 && high == 0 {
		cnsaStatus = "PASSING"
	}

	hndlRisk := "CRITICAL"
	if critical == 0 {
		hndlRisk = "LOW"
	}

	return PDFData{
		Target:         target,
		ScanTime:       time.Now().Format("2006-01-02 15:04:05 MST"),
		TotalEndpoints: total,
		Vulnerable:     vulnerable,
		Critical:       critical,
		High:           high,
		Moderate:       moderate,
		Safe:           safe,
		RiskScore:      pct,
		RiskLevel:      riskLevel,
		VulnerablePct:  pct,
		CNSAStatus:     cnsaStatus,
		HNDLRisk:       hndlRisk,
		MigrationWeeks: migrationWeeks,
		Findings:       findings,
		Services:       services,
		ServiceRisks:   serviceRisks,
	}
}

// ==========================================
// PAGE 1: EXECUTIVE SUMMARY
// ==========================================

func addExecutiveSummary(pdf *fpdf.Fpdf, data PDFData) {
	pdf.AddPage()

	// Header bar
	pdf.SetFillColor(colorPurple.R, colorPurple.G, colorPurple.B)
	pdf.Rect(0, 0, 210, 45, "F")

	// Title
	pdf.SetTextColor(colorWhite.R, colorWhite.G, colorWhite.B)
	pdf.SetFont("Helvetica", "B", 28)
	pdf.SetXY(15, 10)
	pdf.CellFormat(180, 12, "PQScan", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 12)
	pdf.SetXY(15, 22)
	pdf.CellFormat(180, 8, "Post-Quantum Cryptography Vulnerability Report", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetXY(15, 32)
	pdf.CellFormat(180, 6, fmt.Sprintf("Target: %s  |  Date: %s", data.Target, data.ScanTime), "", 1, "L", false, 0, "")

	// Reset text color
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)

	// EXECUTIVE SUMMARY title
	pdf.SetXY(15, 55)
	pdf.SetFont("Helvetica", "B", 16)
	pdf.CellFormat(180, 10, "Executive Summary", "", 1, "L", false, 0, "")

	// Divider line
	pdf.SetDrawColor(colorPurple.R, colorPurple.G, colorPurple.B)
	pdf.SetLineWidth(0.8)
	pdf.Line(15, 66, 195, 66)

	// Risk Score box
	y := 72.0
	scoreColor := getRiskColor(data.RiskLevel)

	// Score card background
	pdf.SetFillColor(scoreColor.R, scoreColor.G, scoreColor.B)
	pdf.RoundedRect(15, y, 60, 45, 4, "1234", "F")

	// Score number
	pdf.SetTextColor(colorWhite.R, colorWhite.G, colorWhite.B)
	pdf.SetFont("Helvetica", "B", 36)
	pdf.SetXY(15, y+5)
	pdf.CellFormat(60, 18, fmt.Sprintf("%.0f", data.RiskScore), "", 1, "C", false, 0, "")

	// Score label
	pdf.SetFont("Helvetica", "", 9)
	pdf.SetXY(15, y+23)
	pdf.CellFormat(60, 6, "Quantum Risk Score", "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetXY(15, y+30)
	pdf.CellFormat(60, 8, data.RiskLevel, "", 1, "C", false, 0, "")

	// Stats next to score
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
	statsX := 85.0

	addStatBox(pdf, statsX, y, "Total Endpoints", fmt.Sprintf("%d", data.TotalEndpoints), colorBlue)
	addStatBox(pdf, statsX+55, y, "Vulnerable", fmt.Sprintf("%d (%.0f%%)", data.Vulnerable, data.VulnerablePct), scoreColor)
	addStatBox(pdf, statsX, y+23, "Critical", fmt.Sprintf("%d", data.Critical), colorCritical)
	addStatBox(pdf, statsX+55, y+23, "Quantum-Safe", fmt.Sprintf("%d", data.Safe), colorSafe)

	// Risk bar
	y = 125.0
	pdf.SetFont("Helvetica", "B", 10)
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
	pdf.SetXY(15, y)
	pdf.CellFormat(180, 6, "Quantum Vulnerability Distribution", "", 1, "L", false, 0, "")

	y += 8
	barWidth := 180.0
	barHeight := 10.0

	// Background
	pdf.SetFillColor(colorLightGray.R, colorLightGray.G, colorLightGray.B)
	pdf.RoundedRect(15, y, barWidth, barHeight, 2, "1234", "F")

	// Fill
	if data.TotalEndpoints > 0 {
		fillWidth := barWidth * data.VulnerablePct / 100
		if fillWidth > 0 {
			pdf.SetFillColor(scoreColor.R, scoreColor.G, scoreColor.B)
			pdf.RoundedRect(15, y, fillWidth, barHeight, 2, "1234", "F")

			// Percentage text on bar
			pdf.SetTextColor(colorWhite.R, colorWhite.G, colorWhite.B)
			pdf.SetFont("Helvetica", "B", 7)
			pdf.SetXY(15, y+1)
			pdf.CellFormat(fillWidth, barHeight-2, fmt.Sprintf("%.0f%% Vulnerable", data.VulnerablePct), "", 0, "C", false, 0, "")
		}
	}

	// Key Findings section
	y = 150.0
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetXY(15, y)
	pdf.CellFormat(180, 8, "Key Findings", "", 1, "L", false, 0, "")

	pdf.SetDrawColor(colorPurple.R, colorPurple.G, colorPurple.B)
	pdf.Line(15, y+9, 195, y+9)

	y += 14

	// Finding bullets
	keyFindings := []struct {
		icon  string
		color pdfColor
		text  string
	}{
		{
			color: colorCritical,
			text:  fmt.Sprintf("%d of %d endpoints (%.0f%%) use encryption that will be completely broken by quantum computers using Shor's algorithm.", data.Vulnerable, data.TotalEndpoints, data.VulnerablePct),
		},
		{
			color: colorCritical,
			text:  "All RSA, ECDSA, ECDH, and Diffie-Hellman based key exchanges are vulnerable. Private keys can be recovered, allowing decryption of all past and future traffic.",
		},
		{
			color: colorModerate,
			text:  "Harvest Now, Decrypt Later (HNDL): Adversaries may already be recording encrypted traffic for future decryption when quantum computers become available.",
		},
	}

	if data.Critical == 0 {
		keyFindings = []struct {
			icon  string
			color pdfColor
			text  string
		}{
			{
				color: colorSafe,
				text:  "All scanned endpoints use quantum-safe cryptographic algorithms. No immediate action is required.",
			},
			{
				color: colorSafe,
				text:  "The infrastructure is compliant with CNSA 2.0 requirements for post-quantum cryptography.",
			},
		}
	}

	for _, finding := range keyFindings {
		// Bullet dot
		pdf.SetFillColor(finding.color.R, finding.color.G, finding.color.B)
		pdf.Circle(20, y+3, 2, "F")

		// Text
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
		pdf.SetXY(26, y)

		// Word wrap
		lines := pdf.SplitText(finding.text, 165)
		for _, line := range lines {
			pdf.SetX(26)
			pdf.CellFormat(165, 5, line, "", 1, "L", false, 0, "")
		}

		y = pdf.GetY() + 4
	}

	// CNSA 2.0 Status box at bottom
	y = 225.0
	if data.CNSAStatus == "FAILING" {
		pdf.SetFillColor(255, 240, 240)
		pdf.SetDrawColor(colorCritical.R, colorCritical.G, colorCritical.B)
	} else {
		pdf.SetFillColor(240, 255, 240)
		pdf.SetDrawColor(colorSafe.R, colorSafe.G, colorSafe.B)
	}
	pdf.SetLineWidth(0.5)
	pdf.RoundedRect(15, y, 180, 30, 3, "1234", "DF")

	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
	pdf.SetXY(20, y+3)
	pdf.CellFormat(170, 7, "CNSA 2.0 Compliance Status", "", 1, "L", false, 0, "")

	if data.CNSAStatus == "FAILING" {
		pdf.SetTextColor(colorCritical.R, colorCritical.G, colorCritical.B)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetXY(20, y+11)
		pdf.CellFormat(170, 6, "FAILING — Migration to post-quantum cryptography required", "", 1, "L", false, 0, "")
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
		pdf.SetXY(20, y+19)
		pdf.CellFormat(170, 5, "NSA mandates complete PQC migration by 2033-2035. All scanned endpoints must transition to approved algorithms.", "", 1, "L", false, 0, "")
	} else {
		pdf.SetTextColor(colorSafe.R, colorSafe.G, colorSafe.B)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetXY(20, y+11)
		pdf.CellFormat(170, 6, "PASSING — All endpoints use quantum-safe algorithms", "", 1, "L", false, 0, "")
	}

	// Footer
	addFooter(pdf, data)
}

// ==========================================
// PAGE 2: RISK BREAKDOWN
// ==========================================

func addRiskBreakdown(pdf *fpdf.Fpdf, data PDFData) {
	pdf.AddPage()

	// Page title
	addPageTitle(pdf, "Risk Analysis & Compliance")

	y := 35.0

	// Service Breakdown Table
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
	pdf.SetXY(15, y)
	pdf.CellFormat(180, 8, "Service Breakdown", "", 1, "L", false, 0, "")
	y += 10

	// Table header
	pdf.SetFillColor(colorDarkBg.R, colorDarkBg.G, colorDarkBg.B)
	pdf.SetTextColor(colorWhite.R, colorWhite.G, colorWhite.B)
	pdf.SetFont("Helvetica", "B", 9)
	pdf.SetXY(15, y)
	pdf.CellFormat(60, 8, "  Service", "1", 0, "L", true, 0, "")
	pdf.CellFormat(35, 8, "Endpoints", "1", 0, "C", true, 0, "")
	pdf.CellFormat(45, 8, "Status", "1", 0, "C", true, 0, "")
	pdf.CellFormat(40, 8, "Action", "1", 1, "C", true, 0, "")
	y += 8

	// Table rows
	pdf.SetFont("Helvetica", "", 9)
	rowIdx := 0
	for service, count := range data.Services {
		risk := data.ServiceRisks[service]

		// Alternating row colors
		if rowIdx%2 == 0 {
			pdf.SetFillColor(colorLightGray.R, colorLightGray.G, colorLightGray.B)
		} else {
			pdf.SetFillColor(colorWhite.R, colorWhite.G, colorWhite.B)
		}

		pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
		pdf.SetXY(15, y)
		pdf.CellFormat(60, 7, "  "+service, "1", 0, "L", true, 0, "")
		pdf.CellFormat(35, 7, fmt.Sprintf("%d", count), "1", 0, "C", true, 0, "")

		if risk == "CRITICAL" {
			pdf.SetTextColor(colorCritical.R, colorCritical.G, colorCritical.B)
			pdf.CellFormat(45, 7, "VULNERABLE", "1", 0, "C", true, 0, "")
			pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
			pdf.CellFormat(40, 7, "Migrate to PQC", "1", 1, "C", true, 0, "")
		} else {
			pdf.SetTextColor(colorSafe.R, colorSafe.G, colorSafe.B)
			pdf.CellFormat(45, 7, "SAFE", "1", 0, "C", true, 0, "")
			pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
			pdf.CellFormat(40, 7, "No action", "1", 1, "C", true, 0, "")
		}
		y += 7
		rowIdx++
	}

	// CNSA 2.0 Timeline
	y += 10
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
	pdf.SetXY(15, y)
	pdf.CellFormat(180, 8, "CNSA 2.0 Compliance Timeline", "", 1, "L", false, 0, "")
	y += 10

	milestones := []struct {
		year   string
		desc   string
		status string
	}{
		{"2025", "Prefer PQC for new systems", data.CNSAStatus},
		{"2027", "All new systems MUST use PQC", data.CNSAStatus},
		{"2030", "Legacy symmetric crypto must be upgraded", data.CNSAStatus},
		{"2033", "All network protocols must be quantum-safe", data.CNSAStatus},
		{"2035", "Complete migration — no exceptions", data.CNSAStatus},
	}

	for _, m := range milestones {
		// Timeline dot
		if m.status == "PASSING" {
			pdf.SetFillColor(colorSafe.R, colorSafe.G, colorSafe.B)
		} else {
			pdf.SetFillColor(colorCritical.R, colorCritical.G, colorCritical.B)
		}
		pdf.Circle(22, y+3, 3, "F")

		// Timeline line
		pdf.SetDrawColor(colorBorder.R, colorBorder.G, colorBorder.B)
		pdf.SetLineWidth(0.3)
		if m.year != "2035" {
			pdf.Line(22, y+6, 22, y+16)
		}

		// Year
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
		pdf.SetXY(30, y)
		pdf.CellFormat(20, 6, m.year, "", 0, "L", false, 0, "")

		// Description
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetXY(52, y)
		pdf.CellFormat(100, 6, m.desc, "", 0, "L", false, 0, "")

		// Status
		if m.status == "PASSING" {
			pdf.SetTextColor(colorSafe.R, colorSafe.G, colorSafe.B)
			pdf.SetXY(155, y)
			pdf.CellFormat(40, 6, "PASSING", "", 0, "R", false, 0, "")
		} else {
			pdf.SetTextColor(colorCritical.R, colorCritical.G, colorCritical.B)
			pdf.SetXY(155, y)
			pdf.CellFormat(40, 6, "FAILING", "", 0, "R", false, 0, "")
		}

		y += 16
	}

	// HNDL Risk Box
	y += 5
	pdf.SetFillColor(255, 248, 240)
	pdf.SetDrawColor(colorHigh.R, colorHigh.G, colorHigh.B)
	pdf.SetLineWidth(0.5)
	pdf.RoundedRect(15, y, 180, 40, 3, "1234", "DF")

	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(colorHigh.R, colorHigh.G, colorHigh.B)
	pdf.SetXY(20, y+3)
	pdf.CellFormat(170, 7, "Harvest Now, Decrypt Later (HNDL) Risk", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)

	hndlText := "Nation-state adversaries are actively recording encrypted traffic. When quantum computers become available, they will decrypt everything captured today. Any data that must remain confidential for more than 10 years is already at risk."

	pdf.SetXY(20, y+12)
	lines := pdf.SplitText(hndlText, 165)
	for _, line := range lines {
		pdf.SetX(20)
		pdf.CellFormat(165, 5, line, "", 1, "L", false, 0, "")
	}

	hndlItems := "At-risk data: trade secrets, health records (HIPAA), financial records, legal communications, classified information."
	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetXY(20, pdf.GetY()+2)
	pdf.CellFormat(165, 5, hndlItems, "", 1, "L", false, 0, "")

	// Migration Estimate
	y = pdf.GetY() + 10
	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
	pdf.SetXY(15, y)
	pdf.CellFormat(90, 8, "Estimated Migration Effort:", "", 0, "L", false, 0, "")

	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(colorPurple.R, colorPurple.G, colorPurple.B)
	pdf.CellFormat(90, 8, data.MigrationWeeks, "", 1, "L", false, 0, "")

	addFooter(pdf, data)
}

// ==========================================
// PAGE 3+: DETAILED FINDINGS
// ==========================================

func addDetailedFindings(pdf *fpdf.Fpdf, data PDFData) {
	pdf.AddPage()
	addPageTitle(pdf, "Detailed Findings")

	y := 35.0

	for i, f := range data.Findings {
		// Check if we need a new page
		neededHeight := 50.0
		if f.HasCert {
			neededHeight = 70.0
		}
		if y+neededHeight > 270 {
			addFooter(pdf, data)
			pdf.AddPage()
			addPageTitle(pdf, "Detailed Findings (continued)")
			y = 35.0
		}

		// Finding card
		rColor := getRiskColor(f.RiskLevel)

		// Left border color bar
		pdf.SetFillColor(rColor.R, rColor.G, rColor.B)
		pdf.Rect(15, y, 3, neededHeight-5, "F")

		// Card background
		pdf.SetFillColor(colorLightGray.R, colorLightGray.G, colorLightGray.B)
		pdf.RoundedRect(18, y, 177, neededHeight-5, 2, "1234", "F")

		// Finding header
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
		pdf.SetXY(22, y+3)

		riskEmoji := "CRITICAL"
		if f.RiskLevel == "SAFE" {
			riskEmoji = "SAFE"
		}
		pdf.CellFormat(120, 6,
			fmt.Sprintf("#%d  %s:%d (%s)", i+1, f.Host, f.Port, f.Service),
			"", 0, "L", false, 0, "")

		// Risk badge
		pdf.SetFillColor(rColor.R, rColor.G, rColor.B)
		pdf.SetTextColor(colorWhite.R, colorWhite.G, colorWhite.B)
		pdf.SetFont("Helvetica", "B", 7)
		badgeX := 165.0
		pdf.RoundedRect(badgeX, y+3, 27, 5, 1, "1234", "F")
		pdf.SetXY(badgeX, y+3)
		pdf.CellFormat(27, 5, riskEmoji, "", 0, "C", false, 0, "")

		// Finding details
		pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
		pdf.SetFont("Helvetica", "", 8)
		detailY := y + 12

		addFindingRow(pdf, 22, detailY, "Protocol:", f.Protocol)
		detailY += 5
		addFindingRow(pdf, 22, detailY, "Cipher Suite:", truncateString(f.CipherSuite, 70))
		detailY += 5
		addFindingRow(pdf, 22, detailY, "Key Exchange:", truncateString(f.KeyExchange, 70))
		detailY += 5

		// Quantum threat
		pdf.SetFont("Helvetica", "B", 8)
		if strings.Contains(f.RiskLevel, "CRITICAL") {
			pdf.SetTextColor(colorCritical.R, colorCritical.G, colorCritical.B)
		} else {
			pdf.SetTextColor(colorSafe.R, colorSafe.G, colorSafe.B)
		}
		addFindingRow(pdf, 22, detailY, "Quantum Threat:", truncateString(f.QuantumThreat, 65))
		detailY += 5

		// Certificate info
		if f.HasCert {
			pdf.SetTextColor(colorTextMuted.R, colorTextMuted.G, colorTextMuted.B)
			pdf.SetFont("Helvetica", "I", 7)
			pdf.SetXY(22, detailY)
			pdf.CellFormat(170, 4, "Certificate:", "", 1, "L", false, 0, "")
			detailY += 4

			pdf.SetFont("Helvetica", "", 7)
			pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)

			certInfo := fmt.Sprintf("%s | %s", f.CertKeyAlg, f.CertSigAlg)
			if f.CertKeySize > 0 {
				certInfo = fmt.Sprintf("%s (%d-bit) | %s", f.CertKeyAlg, f.CertKeySize, f.CertSigAlg)
			}
			pdf.SetXY(22, detailY)
			pdf.CellFormat(100, 4, certInfo, "", 0, "L", false, 0, "")

			pdf.SetXY(125, detailY)
			pdf.CellFormat(65, 4, fmt.Sprintf("Expires: %s", f.CertExpiry), "", 1, "R", false, 0, "")
			detailY += 5
		}

		// Remediation
		pdf.SetFont("Helvetica", "", 7)
		pdf.SetTextColor(colorBlue.R, colorBlue.G, colorBlue.B)
		pdf.SetXY(22, detailY)
		remLines := pdf.SplitText("Fix: "+f.Remediation, 165)
		for _, line := range remLines {
			pdf.SetX(22)
			pdf.CellFormat(165, 4, line, "", 1, "L", false, 0, "")
		}

		y += neededHeight
	}

	addFooter(pdf, data)
}

// ==========================================
// LAST PAGE: RECOMMENDATIONS
// ==========================================

func addRecommendations(pdf *fpdf.Fpdf, data PDFData) {
	pdf.AddPage()
	addPageTitle(pdf, "Recommendations & Next Steps")

	y := 35.0

	recommendations := []struct {
		phase    string
		title    string
		desc     string
		timeline string
	}{
		{
			phase:    "Phase 1",
			title:    "Immediate — Configuration Changes",
			desc:     "Update TLS cipher suite configuration on web servers and load balancers to prefer post-quantum key exchange algorithms. Enable X25519+ML-KEM-768 hybrid key exchange where supported.",
			timeline: "1-2 weeks",
		},
		{
			phase:    "Phase 2",
			title:    "Short-term — Library & Protocol Updates",
			desc:     "Update cryptographic libraries (OpenSSL 3.x, BoringSSL) to versions supporting ML-KEM and ML-DSA. Update SSH server configurations to enable sntrup761x25519-sha512 hybrid key exchange.",
			timeline: "1-3 months",
		},
		{
			phase:    "Phase 3",
			title:    "Medium-term — Certificate Migration",
			desc:     "Work with Certificate Authorities to obtain hybrid or pure post-quantum certificates. Deploy ML-DSA or composite certificates for TLS server authentication.",
			timeline: "3-6 months",
		},
		{
			phase:    "Phase 4",
			title:    "Long-term — Full Architecture Review",
			desc:     "Audit all cryptographic usage across the organization including VPNs (IPSec), email (S/MIME), code signing, database encryption, and key management systems. Implement crypto agility for future algorithm transitions.",
			timeline: "6-18 months",
		},
	}

	if data.Critical == 0 {
		recommendations = []struct {
			phase    string
			title    string
			desc     string
			timeline string
		}{
			{
				phase:    "Ongoing",
				title:    "Maintain Quantum-Safe Posture",
				desc:     "Continue monitoring for algorithm deprecations and new NIST standards. Ensure all new deployments use CNSA 2.0 approved algorithms. Run pqscan regularly to detect regressions.",
				timeline: "Continuous",
			},
		}
	}

	for _, rec := range recommendations {
		if y+35 > 260 {
			addFooter(pdf, data)
			pdf.AddPage()
			addPageTitle(pdf, "Recommendations (continued)")
			y = 35.0
		}

		// Phase badge
		pdf.SetFillColor(colorPurple.R, colorPurple.G, colorPurple.B)
		pdf.SetTextColor(colorWhite.R, colorWhite.G, colorWhite.B)
		pdf.SetFont("Helvetica", "B", 8)
		pdf.RoundedRect(15, y, 22, 6, 2, "1234", "F")
		pdf.SetXY(15, y)
		pdf.CellFormat(22, 6, rec.phase, "", 0, "C", false, 0, "")

		// Timeline
		pdf.SetTextColor(colorTextMuted.R, colorTextMuted.G, colorTextMuted.B)
		pdf.SetFont("Helvetica", "", 8)
		pdf.SetXY(155, y)
		pdf.CellFormat(40, 6, rec.timeline, "", 0, "R", false, 0, "")

		// Title
		pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.SetXY(40, y)
		pdf.CellFormat(110, 6, rec.title, "", 1, "L", false, 0, "")
		y += 8

		// Description
		pdf.SetFont("Helvetica", "", 9)
		pdf.SetXY(40, y)
		lines := pdf.SplitText(rec.desc, 150)
		for _, line := range lines {
			pdf.SetX(40)
			pdf.CellFormat(150, 5, line, "", 1, "L", false, 0, "")
		}
		y = pdf.GetY() + 8
	}

	// Quantum Computing Primer box
	y += 5
	if y+50 > 260 {
		addFooter(pdf, data)
		pdf.AddPage()
		addPageTitle(pdf, "Background")
		y = 35.0
	}

	pdf.SetFillColor(240, 240, 255)
	pdf.SetDrawColor(colorPurple.R, colorPurple.G, colorPurple.B)
	pdf.SetLineWidth(0.5)
	pdf.RoundedRect(15, y, 180, 55, 3, "1234", "DF")

	pdf.SetFont("Helvetica", "B", 11)
	pdf.SetTextColor(colorPurple.R, colorPurple.G, colorPurple.B)
	pdf.SetXY(20, y+3)
	pdf.CellFormat(170, 7, "How Quantum Computers Break Encryption", "", 1, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)

	primerText := []string{
		"Shor's Algorithm: Breaks ALL public-key cryptography currently in use (RSA, ECDSA, ECDH, Diffie-Hellman). An attacker can recover private keys and decrypt all traffic, forge signatures, and impersonate servers.",
		"",
		"Grover's Algorithm: Halves the effective security of symmetric algorithms. AES-128 becomes 64-bit (broken). AES-256 becomes 128-bit (still safe). This is why CNSA 2.0 requires AES-256 minimum.",
		"",
		"Timeline: Experts estimate cryptographically-relevant quantum computers may exist within 10-15 years. The NSA's CNSA 2.0 mandate requires complete migration by 2033-2035.",
	}

	pdf.SetXY(20, y+12)
	for _, line := range primerText {
		if line == "" {
			pdf.SetXY(20, pdf.GetY()+2)
			continue
		}
		wrapped := pdf.SplitText(line, 165)
		for _, w := range wrapped {
			pdf.SetX(20)
			pdf.CellFormat(165, 4, w, "", 1, "L", false, 0, "")
		}
	}

	// About section
	y = pdf.GetY() + 15
	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(colorTextMuted.R, colorTextMuted.G, colorTextMuted.B)
	pdf.SetXY(15, y)
	pdf.CellFormat(180, 5, "This report was generated by pqscan v0.1.0 — an open-source post-quantum cryptography vulnerability scanner.", "", 1, "C", false, 0, "")
	pdf.SetXY(15, y+5)
	pdf.CellFormat(180, 5, "https://github.com/yourorg/pqscan", "", 1, "C", false, 0, "")

	addFooter(pdf, data)
}

// ==========================================
// HELPER FUNCTIONS
// ==========================================

func addPageTitle(pdf *fpdf.Fpdf, title string) {
	// Purple header bar
	pdf.SetFillColor(colorPurple.R, colorPurple.G, colorPurple.B)
	pdf.Rect(0, 0, 210, 25, "F")

	pdf.SetTextColor(colorWhite.R, colorWhite.G, colorWhite.B)
	pdf.SetFont("Helvetica", "B", 16)
	pdf.SetXY(15, 7)
	pdf.CellFormat(130, 10, title, "", 0, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetXY(145, 9)
	pdf.CellFormat(50, 8, "PQScan Report", "", 0, "R", false, 0, "")
}

func addFooter(pdf *fpdf.Fpdf, data PDFData) {
	pdf.SetTextColor(colorTextMuted.R, colorTextMuted.G, colorTextMuted.B)
	pdf.SetFont("Helvetica", "", 7)

	pageNum := pdf.PageNo()

	pdf.SetXY(15, 282)
	pdf.CellFormat(60, 4, fmt.Sprintf("Target: %s", data.Target), "", 0, "L", false, 0, "")
	pdf.CellFormat(60, 4, fmt.Sprintf("Generated: %s", data.ScanTime), "", 0, "C", false, 0, "")
	pdf.CellFormat(60, 4, fmt.Sprintf("Page %d  |  pqscan v0.1.0", pageNum), "", 0, "R", false, 0, "")

	// Footer line
	pdf.SetDrawColor(colorBorder.R, colorBorder.G, colorBorder.B)
	pdf.SetLineWidth(0.3)
	pdf.Line(15, 280, 195, 280)
}

func addStatBox(pdf *fpdf.Fpdf, x, y float64, label, value string, valueColor pdfColor) {
	boxWidth := 50.0
	boxHeight := 20.0

	pdf.SetFillColor(colorLightGray.R, colorLightGray.G, colorLightGray.B)
	pdf.RoundedRect(x, y, boxWidth, boxHeight, 2, "1234", "F")

	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(valueColor.R, valueColor.G, valueColor.B)
	pdf.SetXY(x, y+2)
	pdf.CellFormat(boxWidth, 9, value, "", 1, "C", false, 0, "")

	pdf.SetFont("Helvetica", "", 7)
	pdf.SetTextColor(colorTextMuted.R, colorTextMuted.G, colorTextMuted.B)
	pdf.SetXY(x, y+12)
	pdf.CellFormat(boxWidth, 5, label, "", 1, "C", false, 0, "")
}

func addFindingRow(pdf *fpdf.Fpdf, x, y float64, label, value string) {
	pdf.SetFont("Helvetica", "B", 8)
	pdf.SetTextColor(colorTextMuted.R, colorTextMuted.G, colorTextMuted.B)
	pdf.SetXY(x, y)
	pdf.CellFormat(30, 4, label, "", 0, "L", false, 0, "")

	pdf.SetFont("Helvetica", "", 8)
	pdf.SetTextColor(colorDarkText.R, colorDarkText.G, colorDarkText.B)
	pdf.CellFormat(135, 4, value, "", 0, "L", false, 0, "")
}

func getRiskColor(riskLevel string) pdfColor {
	switch {
	case strings.Contains(riskLevel, "CRITICAL"):
		return colorCritical
	case strings.Contains(riskLevel, "HIGH"):
		return colorHigh
	case strings.Contains(riskLevel, "MODERATE"):
		return colorModerate
	case riskLevel == "SAFE":
		return colorSafe
	default:
		return colorCritical
	}
}

func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}