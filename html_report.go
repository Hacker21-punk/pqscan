package main

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

type HTMLReportData struct {
	Target          string
	ScanTime        string
	Version         string
	TotalEndpoints  int
	Vulnerable      int
	Critical        int
	High            int
	Moderate        int
	Safe            int
	RiskScore       float64
	RiskLevel       string
	RiskColor       string
	VulnerablePct   float64
	SafePct         float64
	Findings        []HTMLFinding
	Services        []HTMLService
	CNSAStatus      string
	HNDLRisk        string
	MigrationWeeks  string
	GeneratedBy     string
}

type HTMLFinding struct {
	Index         int
	Host          string
	Port          int
	Service       string
	Protocol      string
	CipherSuite   string
	KeyExchange   string
	RiskLevel     string
	RiskClass     string
	RiskIcon      string
	QuantumThreat string
	Remediation   string
	CertSubject   string
	CertIssuer    string
	CertKeyAlg    string
	CertKeySize   int
	CertSigAlg    string
	CertExpiry    string
	CertDaysLeft  int
	CertRisk      string
	CertRiskClass string
	HasCert       bool
	HasError      bool
	Error         string
}

type HTMLService struct {
	Name       string
	Count      int
	RiskClass  string
	RiskLabel  string
}

func GenerateHTMLReport(target string, results []ScanResult, outputFile string) error {
	data := buildHTMLData(target, results)

	funcMap := template.FuncMap{
		"divf": func(a, b float64) float64 {
			if b == 0 {
				return 0
			}
			return a / b
		},
		"mulf": func(a, b float64) float64 {
			return a * b
		},
		"intf": func(a int) float64 {
			return float64(a)
		},
	}

	tmpl, err := template.New("report").Funcs(funcMap).Parse(htmlTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}

	var f *os.File
	if outputFile != "" {
		f, err = os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create file: %w", err)
		}
		defer f.Close()
	} else {
		f = os.Stdout
	}

	err = tmpl.Execute(f, data)
	if err != nil {
		return fmt.Errorf("template execution error: %w", err)
	}

	if outputFile != "" {
		fmt.Printf("  HTML report written to: %s\n", outputFile)
	}

	return nil
}
func buildHTMLData(target string, results []ScanResult) HTMLReportData {
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
	safePct := 0.0
	if total > 0 {
		pct = float64(vulnerable) / float64(total) * 100
		safePct = float64(safe) / float64(total) * 100
	}

	riskLevel := "CRITICAL"
	riskColor := "#DC2626"
	if pct == 0 {
		riskLevel = "SAFE"
		riskColor = "#16A34A"
	} else if pct < 30 {
		riskLevel = "LOW"
		riskColor = "#2563EB"
	} else if pct < 70 {
		riskLevel = "MODERATE"
		riskColor = "#CA8A04"
	} else if pct < 90 {
		riskLevel = "HIGH"
		riskColor = "#EA580C"
	}

	// Build findings
	var findings []HTMLFinding
	for i, r := range results {
		f := HTMLFinding{
			Index:         i + 1,
			Host:          r.Host,
			Port:          r.Port,
			Service:       r.Service,
			Protocol:      r.Protocol,
			CipherSuite:   r.CipherSuite,
			KeyExchange:   r.KeyExchange,
			RiskLevel:     r.RiskLevel,
			QuantumThreat: r.QuantumThreat,
			Remediation:   r.Remediation,
		}

		switch {
		case strings.Contains(r.RiskLevel, "CRITICAL"):
			f.RiskClass = "critical"
			f.RiskIcon = "🔴"
		case strings.Contains(r.RiskLevel, "HIGH"):
			f.RiskClass = "high"
			f.RiskIcon = "🟠"
		case strings.Contains(r.RiskLevel, "MODERATE"):
			f.RiskClass = "moderate"
			f.RiskIcon = "🟡"
		case r.RiskLevel == "SAFE":
			f.RiskClass = "safe"
			f.RiskIcon = "🟢"
		default:
			f.RiskClass = "critical"
			f.RiskIcon = "🔴"
		}

		if r.Certificate.Subject != "" {
			f.HasCert = true
			f.CertSubject = r.Certificate.Subject
			f.CertIssuer = r.Certificate.Issuer
			f.CertKeyAlg = r.Certificate.KeyAlgorithm
			f.CertKeySize = r.Certificate.KeySize
			f.CertSigAlg = r.Certificate.SignatureAlg
			f.CertExpiry = r.Certificate.NotAfter.Format("2006-01-02")
			f.CertDaysLeft = int(time.Until(r.Certificate.NotAfter).Hours() / 24)

			certRisk := classifyCertRisk(r.Certificate.KeyAlgorithm)
			f.CertRisk = certRisk
			if strings.Contains(certRisk, "CRITICAL") {
				f.CertRiskClass = "critical"
			} else if strings.Contains(certRisk, "SAFE") {
				f.CertRiskClass = "safe"
			} else {
				f.CertRiskClass = "moderate"
			}
		}

		if r.Error != "" {
			f.HasError = true
			f.Error = r.Error
		}

		findings = append(findings, f)
	}

	// Build service summary
	svcMap := make(map[string]struct{ total, critical int })
	for _, r := range results {
		s := svcMap[r.Service]
		s.total++
		if strings.Contains(r.RiskLevel, "CRITICAL") {
			s.critical++
		}
		svcMap[r.Service] = s
	}

	var services []HTMLService
	for name, s := range svcMap {
		svc := HTMLService{
			Name:  name,
			Count: s.total,
		}
		if s.critical > 0 {
			svc.RiskClass = "critical"
			svc.RiskLabel = "VULNERABLE"
		} else {
			svc.RiskClass = "safe"
			svc.RiskLabel = "SAFE"
		}
		services = append(services, svc)
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

	return HTMLReportData{
		Target:         target,
		ScanTime:       time.Now().Format("2006-01-02 15:04:05 MST"),
		Version:        "0.1.0",
		TotalEndpoints: total,
		Vulnerable:     vulnerable,
		Critical:       critical,
		High:           high,
		Moderate:       moderate,
		Safe:           safe,
		RiskScore:      pct,
		RiskLevel:      riskLevel,
		RiskColor:      riskColor,
		VulnerablePct:  pct,
		SafePct:        safePct,
		Findings:       findings,
		Services:       services,
		CNSAStatus:     cnsaStatus,
		HNDLRisk:       hndlRisk,
		MigrationWeeks: migrationWeeks,
		GeneratedBy:    "pqscan v0.1.0",
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQScan Report — {{.Target}}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  :root {
    --bg: #0F172A;
    --bg-card: #1E293B;
    --bg-card-hover: #334155;
    --text: #F1F5F9;
    --text-dim: #94A3B8;
    --text-muted: #64748B;
    --critical: #DC2626;
    --critical-bg: rgba(220,38,38,0.1);
    --high: #EA580C;
    --high-bg: rgba(234,88,12,0.1);
    --moderate: #CA8A04;
    --moderate-bg: rgba(202,138,4,0.1);
    --safe: #16A34A;
    --safe-bg: rgba(22,163,74,0.1);
    --blue: #3B82F6;
    --blue-bg: rgba(59,130,246,0.1);
    --border: #334155;
    --accent: #8B5CF6;
  }

  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 
                 'Helvetica Neue', Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    min-height: 100vh;
  }

  .container {
    max-width: 1200px;
    margin: 0 auto;
    padding: 2rem;
  }

  /* Header */
  .header {
    text-align: center;
    padding: 3rem 0;
    border-bottom: 1px solid var(--border);
    margin-bottom: 2rem;
  }

  .header h1 {
    font-size: 2.5rem;
    font-weight: 800;
    background: linear-gradient(135deg, #8B5CF6, #3B82F6);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    margin-bottom: 0.5rem;
  }

  .header .subtitle {
    color: var(--text-dim);
    font-size: 1.1rem;
  }

  .header .target {
    font-size: 1.3rem;
    color: var(--text);
    margin-top: 1rem;
    font-family: 'Courier New', monospace;
    background: var(--bg-card);
    display: inline-block;
    padding: 0.5rem 1.5rem;
    border-radius: 8px;
    border: 1px solid var(--border);
  }

  .header .scan-time {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-top: 0.5rem;
  }

  /* Score Card */
  .score-section {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 2rem;
    margin-bottom: 2rem;
  }

  .score-card {
    background: var(--bg-card);
    border-radius: 16px;
    padding: 2.5rem;
    text-align: center;
    border: 1px solid var(--border);
    position: relative;
    overflow: hidden;
  }

  .score-card::before {
    content: '';
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    height: 4px;
    background: {{.RiskColor}};
  }

  .score-number {
    font-size: 5rem;
    font-weight: 900;
    line-height: 1;
    color: {{.RiskColor}};
  }

  .score-label {
    font-size: 1rem;
    color: var(--text-dim);
    margin-top: 0.5rem;
  }

  .score-sublabel {
    font-size: 1.5rem;
    font-weight: 700;
    color: {{.RiskColor}};
    margin-top: 0.25rem;
  }

  /* Stats Grid */
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 1rem;
  }

  .stat-item {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 1.5rem;
    border: 1px solid var(--border);
  }

  .stat-number {
    font-size: 2rem;
    font-weight: 800;
  }

  .stat-number.critical { color: var(--critical); }
  .stat-number.high { color: var(--high); }
  .stat-number.moderate { color: var(--moderate); }
  .stat-number.safe { color: var(--safe); }

  .stat-label {
    font-size: 0.85rem;
    color: var(--text-dim);
    margin-top: 0.25rem;
  }

  /* Risk Bar */
  .risk-bar-container {
    background: var(--bg-card);
    border-radius: 16px;
    padding: 2rem;
    margin-bottom: 2rem;
    border: 1px solid var(--border);
  }

  .risk-bar-header {
    display: flex;
    justify-content: space-between;
    margin-bottom: 1rem;
  }

  .risk-bar-header h3 {
    font-size: 1rem;
    color: var(--text-dim);
  }

  .risk-bar {
    height: 32px;
    background: var(--bg);
    border-radius: 16px;
    overflow: hidden;
    display: flex;
  }

  .risk-bar-fill {
    height: 100%;
    transition: width 1s ease;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 0.8rem;
    font-weight: 700;
    color: white;
    min-width: 40px;
  }

  .risk-bar-fill.critical { background: var(--critical); }
  .risk-bar-fill.high { background: var(--high); }
  .risk-bar-fill.moderate { background: var(--moderate); }
  .risk-bar-fill.safe { background: var(--safe); }

  /* Section Headers */
  .section {
    margin-bottom: 2rem;
  }

  .section h2 {
    font-size: 1.5rem;
    font-weight: 700;
    margin-bottom: 1rem;
    padding-bottom: 0.5rem;
    border-bottom: 2px solid var(--border);
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .section h2 .icon {
    font-size: 1.3rem;
  }

  /* Service Cards */
  .service-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem;
  }

  .service-card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 1.25rem;
    border: 1px solid var(--border);
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .service-name {
    font-weight: 600;
    font-size: 0.95rem;
  }

  .service-count {
    color: var(--text-dim);
    font-size: 0.85rem;
  }

  .service-badge {
    font-size: 0.75rem;
    font-weight: 700;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    text-transform: uppercase;
  }

  .service-badge.critical {
    background: var(--critical-bg);
    color: var(--critical);
    border: 1px solid var(--critical);
  }

  .service-badge.safe {
    background: var(--safe-bg);
    color: var(--safe);
    border: 1px solid var(--safe);
  }

  /* Finding Cards */
  .finding-card {
    background: var(--bg-card);
    border-radius: 12px;
    padding: 1.5rem;
    margin-bottom: 1rem;
    border: 1px solid var(--border);
    transition: border-color 0.2s;
  }

  .finding-card:hover {
    border-color: var(--text-muted);
  }

  .finding-card.critical { border-left: 4px solid var(--critical); }
  .finding-card.high { border-left: 4px solid var(--high); }
  .finding-card.moderate { border-left: 4px solid var(--moderate); }
  .finding-card.safe { border-left: 4px solid var(--safe); }

  .finding-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 1rem;
  }

  .finding-title {
    font-size: 1.1rem;
    font-weight: 700;
    font-family: 'Courier New', monospace;
  }

  .finding-badge {
    font-size: 0.75rem;
    font-weight: 700;
    padding: 0.25rem 0.75rem;
    border-radius: 9999px;
    text-transform: uppercase;
  }

  .finding-badge.critical {
    background: var(--critical-bg);
    color: var(--critical);
  }

  .finding-badge.high {
    background: var(--high-bg);
    color: var(--high);
  }

  .finding-badge.moderate {
    background: var(--moderate-bg);
    color: var(--moderate);
  }

  .finding-badge.safe {
    background: var(--safe-bg);
    color: var(--safe);
  }

  .finding-grid {
    display: grid;
    grid-template-columns: 140px 1fr;
    gap: 0.4rem 1rem;
    font-size: 0.9rem;
  }

  .finding-label {
    color: var(--text-muted);
    font-weight: 500;
  }

  .finding-value {
    color: var(--text);
    font-family: 'Courier New', monospace;
    font-size: 0.85rem;
    word-break: break-all;
  }

  .finding-value.critical { color: var(--critical); }
  .finding-value.safe { color: var(--safe); }

  .finding-divider {
    border: none;
    border-top: 1px solid var(--border);
    margin: 1rem 0;
  }

  .finding-remediation {
    background: var(--blue-bg);
    border: 1px solid rgba(59,130,246,0.3);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    margin-top: 1rem;
    font-size: 0.85rem;
    color: var(--blue);
  }

  .finding-remediation strong {
    color: #60A5FA;
  }

  .finding-warning {
    background: rgba(234,179,8,0.1);
    border: 1px solid rgba(234,179,8,0.3);
    border-radius: 8px;
    padding: 0.75rem 1rem;
    margin-top: 0.75rem;
    font-size: 0.85rem;
    color: #FBBF24;
  }

  /* Certificate Section inside finding */
  .cert-section {
    background: rgba(0,0,0,0.2);
    border-radius: 8px;
    padding: 1rem;
    margin-top: 0.75rem;
  }

  .cert-section h4 {
    font-size: 0.85rem;
    color: var(--text-dim);
    margin-bottom: 0.5rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }

  /* CNSA Timeline */
  .timeline {
    position: relative;
    padding-left: 2rem;
  }

  .timeline::before {
    content: '';
    position: absolute;
    left: 7px;
    top: 0;
    bottom: 0;
    width: 2px;
    background: var(--border);
  }

  .timeline-item {
    position: relative;
    padding: 1rem 0 1rem 1.5rem;
  }

  .timeline-dot {
    position: absolute;
    left: -1.55rem;
    top: 1.35rem;
    width: 16px;
    height: 16px;
    border-radius: 50%;
    border: 3px solid var(--bg);
  }

  .timeline-dot.failing { background: var(--critical); }
  .timeline-dot.passing { background: var(--safe); }

  .timeline-year {
    font-weight: 800;
    font-size: 1.1rem;
    color: var(--text);
  }

  .timeline-desc {
    color: var(--text-dim);
    font-size: 0.9rem;
  }

  .timeline-status {
    font-weight: 700;
    font-size: 0.85rem;
    margin-top: 0.25rem;
  }

  .timeline-status.failing { color: var(--critical); }
  .timeline-status.passing { color: var(--safe); }

  /* HNDL Warning */
  .hndl-warning {
    background: linear-gradient(135deg, rgba(220,38,38,0.1), rgba(234,88,12,0.1));
    border: 1px solid rgba(220,38,38,0.3);
    border-radius: 16px;
    padding: 2rem;
    margin-bottom: 2rem;
  }

  .hndl-warning h3 {
    color: var(--critical);
    font-size: 1.2rem;
    margin-bottom: 1rem;
  }

  .hndl-warning p {
    color: var(--text-dim);
    margin-bottom: 0.75rem;
    font-size: 0.95rem;
  }

  .hndl-warning ul {
    list-style: none;
    padding: 0;
  }

  .hndl-warning li {
    color: var(--text-dim);
    padding: 0.25rem 0;
    padding-left: 1.5rem;
    position: relative;
    font-size: 0.9rem;
  }

  .hndl-warning li::before {
    content: '⚠';
    position: absolute;
    left: 0;
  }

  /* Migration Card */
  .migration-card {
    background: var(--bg-card);
    border-radius: 16px;
    padding: 2rem;
    border: 1px solid var(--border);
    margin-bottom: 2rem;
  }

  .migration-estimate {
    font-size: 2rem;
    font-weight: 800;
    color: var(--accent);
    margin: 0.5rem 0;
  }

  /* Footer */
  .footer {
    text-align: center;
    padding: 3rem 0;
    border-top: 1px solid var(--border);
    margin-top: 2rem;
  }

  .footer p {
    color: var(--text-muted);
    font-size: 0.85rem;
    margin-bottom: 0.5rem;
  }

  .footer a {
    color: var(--blue);
    text-decoration: none;
  }

  .footer a:hover {
    text-decoration: underline;
  }

  .cta-button {
    display: inline-block;
    margin-top: 1.5rem;
    padding: 0.75rem 2rem;
    background: linear-gradient(135deg, #8B5CF6, #3B82F6);
    color: white;
    border-radius: 9999px;
    text-decoration: none;
    font-weight: 700;
    font-size: 1rem;
    transition: opacity 0.2s;
  }

  .cta-button:hover {
    opacity: 0.9;
    text-decoration: none;
  }

  /* Responsive */
  @media (max-width: 768px) {
    .container { padding: 1rem; }
    .score-section { grid-template-columns: 1fr; }
    .stats-grid { grid-template-columns: 1fr; }
    .score-number { font-size: 3.5rem; }
    .finding-grid { grid-template-columns: 1fr; }
    .service-grid { grid-template-columns: 1fr; }
    .header h1 { font-size: 1.8rem; }
  }

  /* Print */
  @media print {
    body { background: white; color: black; }
    .container { max-width: 100%; }
    .finding-card { break-inside: avoid; }
    .cta-button { display: none; }
    .score-card::before { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
  }
</style>
</head>
<body>

<div class="container">

  <!-- HEADER -->
  <div class="header">
    <h1>⚛ PQScan</h1>
    <div class="subtitle">Post-Quantum Cryptography Vulnerability Report</div>
    <div class="target">{{.Target}}</div>
    <div class="scan-time">Scanned: {{.ScanTime}}</div>
  </div>

  <!-- SCORE + STATS -->
  <div class="score-section">
    <div class="score-card">
      <div class="score-number">{{printf "%.0f" .RiskScore}}</div>
      <div class="score-label">Quantum Risk Score (out of 100)</div>
      <div class="score-sublabel">{{.RiskLevel}}</div>
    </div>
    <div class="stats-grid">
      <div class="stat-item">
        <div class="stat-number critical">{{.Critical}}</div>
        <div class="stat-label">🔴 Critical — Broken by Shor's algorithm</div>
      </div>
      <div class="stat-item">
        <div class="stat-number high">{{.High}}</div>
        <div class="stat-label">🟠 High — Severely weakened</div>
      </div>
      <div class="stat-item">
        <div class="stat-number moderate">{{.Moderate}}</div>
        <div class="stat-label">🟡 Moderate — Weakened but usable</div>
      </div>
      <div class="stat-item">
        <div class="stat-number safe">{{.Safe}}</div>
        <div class="stat-label">🟢 Safe — Quantum-resistant</div>
      </div>
    </div>
  </div>

  <!-- RISK BAR -->
  <div class="risk-bar-container">
    <div class="risk-bar-header">
      <h3>Quantum Vulnerability Distribution</h3>
      <h3>{{.TotalEndpoints}} endpoints scanned</h3>
    </div>
    <div class="risk-bar">
      {{if gt .Critical 0}}
      <div class="risk-bar-fill critical" style="width: {{printf "%.1f" (divf (mulf (intf .Critical) 100.0) (intf .TotalEndpoints))}}%">{{.Critical}}</div>
      {{end}}
      {{if gt .High 0}}
      <div class="risk-bar-fill high" style="width: {{printf "%.1f" (divf (mulf (intf .High) 100.0) (intf .TotalEndpoints))}}%">{{.High}}</div>
      {{end}}
      {{if gt .Moderate 0}}
      <div class="risk-bar-fill moderate" style="width: {{printf "%.1f" (divf (mulf (intf .Moderate) 100.0) (intf .TotalEndpoints))}}%">{{.Moderate}}</div>
      {{end}}
      {{if gt .Safe 0}}
      <div class="risk-bar-fill safe" style="width: {{printf "%.1f" (divf (mulf (intf .Safe) 100.0) (intf .TotalEndpoints))}}%">{{.Safe}}</div>
      {{end}}
    </div>
  </div>

  <!-- SERVICE BREAKDOWN -->
  <div class="section">
    <h2><span class="icon">📡</span> Service Breakdown</h2>
    <div class="service-grid">
      {{range .Services}}
      <div class="service-card">
        <div>
          <div class="service-name">{{.Name}}</div>
          <div class="service-count">{{.Count}} endpoint{{if gt .Count 1}}s{{end}}</div>
        </div>
        <span class="service-badge {{.RiskClass}}">{{.RiskLabel}}</span>
      </div>
      {{end}}
    </div>
  </div>

  <!-- DETAILED FINDINGS -->
  <div class="section">
    <h2><span class="icon">🔍</span> Detailed Findings</h2>
    {{range .Findings}}
    <div class="finding-card {{.RiskClass}}">
      <div class="finding-header">
        <span class="finding-title">{{.RiskIcon}} {{.Host}}:{{.Port}}</span>
        <span class="finding-badge {{.RiskClass}}">{{.RiskLevel}}</span>
      </div>

      <div class="finding-grid">
        <span class="finding-label">Service</span>
        <span class="finding-value">{{.Service}}</span>

        <span class="finding-label">Protocol</span>
        <span class="finding-value">{{.Protocol}}</span>

        <span class="finding-label">Cipher Suite</span>
        <span class="finding-value">{{.CipherSuite}}</span>

        <span class="finding-label">Key Exchange</span>
        <span class="finding-value {{.RiskClass}}">{{.KeyExchange}}</span>

        <span class="finding-label">Quantum Threat</span>
        <span class="finding-value {{.RiskClass}}">{{.QuantumThreat}}</span>
      </div>

      {{if .HasCert}}
      <hr class="finding-divider">
      <div class="cert-section">
        <h4>📜 Certificate</h4>
        <div class="finding-grid">
          <span class="finding-label">Subject</span>
          <span class="finding-value">{{.CertSubject}}</span>

          <span class="finding-label">Issuer</span>
          <span class="finding-value">{{.CertIssuer}}</span>

          <span class="finding-label">Key Algorithm</span>
          <span class="finding-value">{{.CertKeyAlg}}{{if gt .CertKeySize 0}} ({{.CertKeySize}}-bit){{end}}</span>

          <span class="finding-label">Signature</span>
          <span class="finding-value">{{.CertSigAlg}}</span>

          <span class="finding-label">Expires</span>
          <span class="finding-value">{{.CertExpiry}} ({{.CertDaysLeft}} days)</span>

          <span class="finding-label">Quantum Risk</span>
          <span class="finding-value {{.CertRiskClass}}">{{.CertRisk}}</span>
        </div>
      </div>
      {{end}}

      {{if .HasError}}
      <div class="finding-warning">⚠ {{.Error}}</div>
      {{end}}

      <div class="finding-remediation">
        <strong>Remediation:</strong> {{.Remediation}}
      </div>
    </div>
    {{end}}
  </div>

  <!-- CNSA 2.0 TIMELINE -->
  <div class="section">
    <h2><span class="icon">📅</span> CNSA 2.0 Compliance Timeline</h2>
    <div class="timeline">
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2025</div>
        <div class="timeline-desc">Prefer post-quantum algorithms for new systems</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">
          {{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}
        </div>
      </div>
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2027</div>
        <div class="timeline-desc">All new systems MUST use post-quantum cryptography</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">
          {{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}
        </div>
      </div>
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2030</div>
        <div class="timeline-desc">Legacy symmetric crypto and hashing must be upgraded</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">
          {{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}
        </div>
      </div>
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2033</div>
        <div class="timeline-desc">All network protocols must be quantum-safe</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">
          {{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}
        </div>
      </div>
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2035</div>
        <div class="timeline-desc">Complete migration — no exceptions</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">
          {{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}
        </div>
      </div>
    </div>
  </div>

  <!-- HNDL WARNING -->
  {{if gt .Critical 0}}
  <div class="hndl-warning">
    <h3>⚠ Harvest Now, Decrypt Later (HNDL) Risk: {{.HNDLRisk}}</h3>
    <p>
      Nation-state adversaries are <strong>actively recording</strong> encrypted 
      traffic today. When quantum computers become available, they will decrypt 
      everything captured.
    </p>
    <p>
      Any data that must remain confidential for more than 10 years is 
      <strong>already at risk</strong>. This includes:
    </p>
    <ul>
      <li>Trade secrets and intellectual property</li>
      <li>Health records (HIPAA: 50+ year retention)</li>
      <li>Financial records (7+ year retention)</li>
      <li>Attorney-client privileged communications</li>
      <li>Government classified information</li>
      <li>M&A discussions and strategic plans</li>
    </ul>
  </div>
  {{end}}

  <!-- MIGRATION ESTIMATE -->
  <div class="migration-card">
    <h2><span class="icon">🔧</span> Migration Estimate</h2>
    <div class="migration-estimate">{{.MigrationWeeks}}</div>
    <p style="color: var(--text-dim); margin-top: 0.5rem;">
      Estimated time to migrate {{.Vulnerable}} vulnerable endpoint{{if gt .Vulnerable 1}}s{{end}} 
      to post-quantum cryptography.
    </p>
  </div>

  <!-- FOOTER -->
  <div class="footer">
    <p>Generated by {{.GeneratedBy}}</p>
    <p>
      <a href="https://github.com/yourorg/pqscan">github.com/yourorg/pqscan</a>
    </p>
    <p style="margin-top: 1rem; color: var(--text-dim); font-style: italic;">
      "The largest cryptographic migration in history starts with knowing what you have."
    </p>
    <a href="https://yourproduct.com" class="cta-button">
      Get Automated Migration →
    </a>
  </div>

</div>

</body>
</html>`