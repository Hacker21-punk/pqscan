package main

import (
	"fmt"
	"html/template"
	"os"
	"strings"
	"time"
)

type AggregateHTMLData struct {
	ScanTime        string
	Version         string
	TotalTargets    int
	TotalEndpoints  int
	TotalVulnerable int
	TotalCritical   int
	TotalHigh       int
	TotalModerate   int
	TotalSafe       int
	OverallScore    float64
	RiskLevel       string
	RiskColor       string
	ScanDuration    string
	Targets         []AggregateHTMLTarget
	CNSAStatus      string
	HNDLRisk        string
}

type AggregateHTMLTarget struct {
	Name           string
	Endpoints      int
	Critical       int
	Safe           int
	Vulnerable     int
	VulnerablePct  float64
	RiskClass      string
	RiskLabel      string
	Findings       []HTMLFinding
	HasError       bool
	Error          string
}

func GenerateAggregateHTMLReport(report AggregateReport, outputFile string) error {
	data := buildAggregateHTMLData(report)

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

	tmpl, err := template.New("aggregate").Funcs(funcMap).Parse(aggregateHTMLTemplate)
	if err != nil {
		return fmt.Errorf("template parse error: %w", err)
	}

	f, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create file: %w", err)
	}
	defer f.Close()

	err = tmpl.Execute(f, data)
	if err != nil {
		return fmt.Errorf("template execution error: %w", err)
	}

	fmt.Printf("  HTML report written to: %s\n", outputFile)
	return nil
}

func buildAggregateHTMLData(report AggregateReport) AggregateHTMLData {
	riskLevel := "CRITICAL"
	riskColor := "#DC2626"
	score := report.OverallScore

	if score == 0 {
		riskLevel = "SAFE"
		riskColor = "#16A34A"
	} else if score < 30 {
		riskLevel = "LOW"
		riskColor = "#2563EB"
	} else if score < 70 {
		riskLevel = "MODERATE"
		riskColor = "#CA8A04"
	} else if score < 90 {
		riskLevel = "HIGH"
		riskColor = "#EA580C"
	}

	cnsaStatus := "FAILING"
	if report.TotalCritical == 0 && report.TotalHigh == 0 {
		cnsaStatus = "PASSING"
	}

	hndlRisk := "CRITICAL"
	if report.TotalCritical == 0 {
		hndlRisk = "LOW"
	}

	// Build per-target data
	var htmlTargets []AggregateHTMLTarget

	for _, tr := range report.Targets {
		ht := AggregateHTMLTarget{
			Name: tr.Target,
		}

		if tr.Error != nil {
			ht.HasError = true
			ht.Error = tr.Error.Error()
			ht.RiskClass = "moderate"
			ht.RiskLabel = "ERROR"
			htmlTargets = append(htmlTargets, ht)
			continue
		}

		ht.Endpoints = len(tr.Results)

		for _, r := range tr.Results {
			switch {
			case strings.Contains(r.RiskLevel, "CRITICAL"):
				ht.Critical++
			case r.RiskLevel == "SAFE":
				ht.Safe++
			}
		}

		ht.Vulnerable = ht.Endpoints - ht.Safe
		if ht.Endpoints > 0 {
			ht.VulnerablePct = float64(ht.Vulnerable) / float64(ht.Endpoints) * 100
		}

		if ht.Critical > 0 {
			ht.RiskClass = "critical"
			ht.RiskLabel = "VULNERABLE"
		} else {
			ht.RiskClass = "safe"
			ht.RiskLabel = "SAFE"
		}

		// Build findings for this target
		for i, r := range tr.Results {
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
			case r.RiskLevel == "SAFE":
				f.RiskClass = "safe"
				f.RiskIcon = "🟢"
			default:
				f.RiskClass = "moderate"
				f.RiskIcon = "🟡"
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

			ht.Findings = append(ht.Findings, f)
		}

		htmlTargets = append(htmlTargets, ht)
	}

	return AggregateHTMLData{
		ScanTime:        time.Now().Format("2006-01-02 15:04:05 MST"),
		Version:         "0.1.0",
		TotalTargets:    report.TotalTargets,
		TotalEndpoints:  report.TotalEndpoints,
		TotalVulnerable: report.TotalVulnerable,
		TotalCritical:   report.TotalCritical,
		TotalHigh:       report.TotalHigh,
		TotalModerate:   report.TotalModerate,
		TotalSafe:       report.TotalSafe,
		OverallScore:    score,
		RiskLevel:       riskLevel,
		RiskColor:       riskColor,
		ScanDuration:    report.ScanTime.Round(time.Millisecond).String(),
		Targets:         htmlTargets,
		CNSAStatus:      cnsaStatus,
		HNDLRisk:        hndlRisk,
	}
}

const aggregateHTMLTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PQScan Aggregate Report — {{.TotalTargets}} Targets</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  :root {
    --bg: #0F172A; --bg-card: #1E293B; --bg-card-hover: #334155;
    --text: #F1F5F9; --text-dim: #94A3B8; --text-muted: #64748B;
    --critical: #DC2626; --critical-bg: rgba(220,38,38,0.1);
    --high: #EA580C; --high-bg: rgba(234,88,12,0.1);
    --moderate: #CA8A04; --moderate-bg: rgba(202,138,4,0.1);
    --safe: #16A34A; --safe-bg: rgba(22,163,74,0.1);
    --blue: #3B82F6; --blue-bg: rgba(59,130,246,0.1);
    --border: #334155; --accent: #8B5CF6;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Arial, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
  }
  .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }

  .header { text-align: center; padding: 3rem 0; border-bottom: 1px solid var(--border); margin-bottom: 2rem; }
  .header h1 { font-size: 2.5rem; font-weight: 800; background: linear-gradient(135deg, #8B5CF6, #3B82F6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; }
  .header .subtitle { color: var(--text-dim); font-size: 1.1rem; margin-top: 0.5rem; }
  .header .meta { color: var(--text-muted); font-size: 0.85rem; margin-top: 1rem; }

  .score-section { display: grid; grid-template-columns: 1fr 1fr; gap: 2rem; margin-bottom: 2rem; }
  .score-card { background: var(--bg-card); border-radius: 16px; padding: 2.5rem; text-align: center; border: 1px solid var(--border); position: relative; overflow: hidden; }
  .score-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 4px; background: {{.RiskColor}}; }
  .score-number { font-size: 5rem; font-weight: 900; line-height: 1; color: {{.RiskColor}}; }
  .score-label { font-size: 1rem; color: var(--text-dim); margin-top: 0.5rem; }
  .score-sublabel { font-size: 1.5rem; font-weight: 700; color: {{.RiskColor}}; margin-top: 0.25rem; }

  .stats-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 1rem; }
  .stat-item { background: var(--bg-card); border-radius: 12px; padding: 1.5rem; border: 1px solid var(--border); }
  .stat-number { font-size: 2rem; font-weight: 800; }
  .stat-number.critical { color: var(--critical); }
  .stat-number.high { color: var(--high); }
  .stat-number.moderate { color: var(--moderate); }
  .stat-number.safe { color: var(--safe); }
  .stat-label { font-size: 0.85rem; color: var(--text-dim); margin-top: 0.25rem; }

  .section { margin-bottom: 2rem; }
  .section h2 { font-size: 1.5rem; font-weight: 700; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--border); }

  .target-card { background: var(--bg-card); border-radius: 12px; margin-bottom: 1.5rem; border: 1px solid var(--border); overflow: hidden; }
  .target-card.critical { border-left: 4px solid var(--critical); }
  .target-card.safe { border-left: 4px solid var(--safe); }
  .target-card.moderate { border-left: 4px solid var(--moderate); }

  .target-header { padding: 1.25rem 1.5rem; display: flex; justify-content: space-between; align-items: center; cursor: pointer; }
  .target-header:hover { background: var(--bg-card-hover); }
  .target-name { font-size: 1.1rem; font-weight: 700; font-family: 'Courier New', monospace; }
  .target-stats { display: flex; gap: 1rem; align-items: center; }
  .target-badge { font-size: 0.75rem; font-weight: 700; padding: 0.25rem 0.75rem; border-radius: 9999px; text-transform: uppercase; }
  .target-badge.critical { background: var(--critical-bg); color: var(--critical); border: 1px solid var(--critical); }
  .target-badge.safe { background: var(--safe-bg); color: var(--safe); border: 1px solid var(--safe); }
  .target-badge.moderate { background: var(--moderate-bg); color: var(--moderate); border: 1px solid var(--moderate); }

  .target-details { padding: 0 1.5rem 1.5rem; display: none; }
  .target-card.open .target-details { display: block; }

  .target-bar { height: 8px; background: var(--bg); border-radius: 4px; overflow: hidden; margin: 0 1.5rem 0; }
  .target-bar-fill { height: 100%; border-radius: 4px; }
  .target-bar-fill.critical { background: var(--critical); }
  .target-bar-fill.safe { background: var(--safe); }

  .finding-mini { padding: 0.75rem 1rem; margin-top: 0.5rem; background: rgba(0,0,0,0.2); border-radius: 8px; font-size: 0.85rem; }
  .finding-mini-header { display: flex; justify-content: space-between; align-items: center; }
  .finding-mini-title { font-family: 'Courier New', monospace; font-weight: 600; }
  .finding-mini-detail { color: var(--text-dim); margin-top: 0.25rem; font-size: 0.8rem; }

  .finding-mini-badge { font-size: 0.7rem; font-weight: 700; padding: 0.15rem 0.5rem; border-radius: 9999px; }
  .finding-mini-badge.critical { background: var(--critical-bg); color: var(--critical); }
  .finding-mini-badge.safe { background: var(--safe-bg); color: var(--safe); }
  .finding-mini-badge.moderate { background: var(--moderate-bg); color: var(--moderate); }

  .remediation-text { color: var(--blue); font-size: 0.8rem; margin-top: 0.25rem; }

  .cert-mini { color: var(--text-muted); font-size: 0.8rem; margin-top: 0.25rem; }

  .hndl-warning { background: linear-gradient(135deg, rgba(220,38,38,0.1), rgba(234,88,12,0.1)); border: 1px solid rgba(220,38,38,0.3); border-radius: 16px; padding: 2rem; margin-bottom: 2rem; }
  .hndl-warning h3 { color: var(--critical); font-size: 1.2rem; margin-bottom: 1rem; }
  .hndl-warning p { color: var(--text-dim); margin-bottom: 0.75rem; font-size: 0.95rem; }
  .hndl-warning li { color: var(--text-dim); padding: 0.25rem 0 0.25rem 1.5rem; position: relative; font-size: 0.9rem; list-style: none; }
  .hndl-warning li::before { content: '⚠'; position: absolute; left: 0; }

  .timeline { position: relative; padding-left: 2rem; }
  .timeline::before { content: ''; position: absolute; left: 7px; top: 0; bottom: 0; width: 2px; background: var(--border); }
  .timeline-item { position: relative; padding: 1rem 0 1rem 1.5rem; }
  .timeline-dot { position: absolute; left: -1.55rem; top: 1.35rem; width: 16px; height: 16px; border-radius: 50%; border: 3px solid var(--bg); }
  .timeline-dot.failing { background: var(--critical); }
  .timeline-dot.passing { background: var(--safe); }
  .timeline-year { font-weight: 800; font-size: 1.1rem; }
  .timeline-desc { color: var(--text-dim); font-size: 0.9rem; }
  .timeline-status { font-weight: 700; font-size: 0.85rem; margin-top: 0.25rem; }
  .timeline-status.failing { color: var(--critical); }
  .timeline-status.passing { color: var(--safe); }

  .footer { text-align: center; padding: 3rem 0; border-top: 1px solid var(--border); margin-top: 2rem; }
  .footer p { color: var(--text-muted); font-size: 0.85rem; margin-bottom: 0.5rem; }
  .footer a { color: var(--blue); text-decoration: none; }
  .cta-button { display: inline-block; margin-top: 1.5rem; padding: 0.75rem 2rem; background: linear-gradient(135deg, #8B5CF6, #3B82F6); color: white; border-radius: 9999px; text-decoration: none; font-weight: 700; }

  @media (max-width: 768px) {
    .container { padding: 1rem; }
    .score-section { grid-template-columns: 1fr; }
    .stats-grid { grid-template-columns: 1fr; }
    .score-number { font-size: 3.5rem; }
  }

  @media print {
    body { background: white; color: black; }
    .cta-button { display: none; }
  }
</style>
</head>
<body>

<div class="container">
  <div class="header">
    <h1>⚛ PQScan — Aggregate Report</h1>
    <div class="subtitle">Post-Quantum Cryptography Vulnerability Assessment</div>
    <div class="meta">
      {{.TotalTargets}} targets scanned • {{.ScanTime}} • Duration: {{.ScanDuration}}
    </div>
  </div>

  <div class="score-section">
    <div class="score-card">
      <div class="score-number">{{printf "%.0f" .OverallScore}}</div>
      <div class="score-label">Aggregate Quantum Risk Score</div>
      <div class="score-sublabel">{{.RiskLevel}}</div>
    </div>
    <div class="stats-grid">
      <div class="stat-item">
        <div class="stat-number critical">{{.TotalCritical}}</div>
        <div class="stat-label">🔴 Critical — Broken by quantum</div>
      </div>
      <div class="stat-item">
        <div class="stat-number high">{{.TotalHigh}}</div>
        <div class="stat-label">🟠 High — Severely weakened</div>
      </div>
      <div class="stat-item">
        <div class="stat-number moderate">{{.TotalModerate}}</div>
        <div class="stat-label">🟡 Moderate — Weakened</div>
      </div>
      <div class="stat-item">
        <div class="stat-number safe">{{.TotalSafe}}</div>
        <div class="stat-label">🟢 Safe — Quantum-resistant</div>
      </div>
    </div>
  </div>

  <div class="section">
    <h2>🎯 Per-Target Results</h2>
    {{range .Targets}}
    <div class="target-card {{.RiskClass}}" onclick="this.classList.toggle('open')">
      <div class="target-header">
        <div>
          <span class="target-name">{{.Name}}</span>
          <span style="color: var(--text-muted); font-size: 0.85rem; margin-left: 0.5rem;">
            {{if .HasError}}error{{else}}{{.Endpoints}} endpoint{{if gt .Endpoints 1}}s{{end}}{{end}}
          </span>
        </div>
        <div class="target-stats">
          {{if .HasError}}
          <span class="target-badge moderate">ERROR</span>
          {{else if gt .Critical 0}}
          <span style="color: var(--text-muted); font-size: 0.85rem;">{{.Vulnerable}}/{{.Endpoints}} vulnerable</span>
          <span class="target-badge critical">{{printf "%.0f" .VulnerablePct}}% AT RISK</span>
          {{else}}
          <span class="target-badge safe">QUANTUM SAFE</span>
          {{end}}
        </div>
      </div>

      {{if not .HasError}}
      <div class="target-bar">
        {{if gt .Critical 0}}
        <div class="target-bar-fill critical" style="width: {{printf "%.1f" .VulnerablePct}}%"></div>
        {{else}}
        <div class="target-bar-fill safe" style="width: 100%"></div>
        {{end}}
      </div>
      {{end}}

      <div class="target-details">
        {{if .HasError}}
        <p style="color: var(--critical); padding: 1rem 0;">{{.Error}}</p>
        {{else}}
        {{range .Findings}}
        <div class="finding-mini">
          <div class="finding-mini-header">
            <span class="finding-mini-title">{{.RiskIcon}} :{{.Port}}/{{.Service}}</span>
            <span class="finding-mini-badge {{.RiskClass}}">{{.RiskLevel}}</span>
          </div>
          <div class="finding-mini-detail">
            {{.Protocol}} — {{.CipherSuite}}
          </div>
          {{if .HasCert}}
          <div class="cert-mini">
            📜 {{.CertKeyAlg}}{{if gt .CertKeySize 0}} ({{.CertKeySize}}-bit){{end}} — {{.CertRisk}}
          </div>
          {{end}}
          <div class="remediation-text">
            💡 {{.Remediation}}
          </div>
        </div>
        {{end}}
        {{end}}
      </div>
    </div>
    {{end}}
  </div>

  <!-- CNSA 2.0 Timeline -->
  <div class="section">
    <h2>📅 CNSA 2.0 Compliance</h2>
    <div class="timeline">
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2025</div>
        <div class="timeline-desc">Prefer PQC for new systems</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">{{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}</div>
      </div>
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2027</div>
        <div class="timeline-desc">New systems MUST use PQC</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">{{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}</div>
      </div>
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2033</div>
        <div class="timeline-desc">All protocols must be quantum-safe</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">{{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}</div>
      </div>
      <div class="timeline-item">
        <div class="timeline-dot {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}"></div>
        <div class="timeline-year">2035</div>
        <div class="timeline-desc">Complete migration — no exceptions</div>
        <div class="timeline-status {{if eq $.CNSAStatus "PASSING"}}passing{{else}}failing{{end}}">{{if eq $.CNSAStatus "PASSING"}}✅ PASSING{{else}}❌ FAILING{{end}}</div>
      </div>
    </div>
  </div>

  {{if gt .TotalCritical 0}}
  <div class="hndl-warning">
    <h3>⚠ Harvest Now, Decrypt Later — Risk Across All Targets</h3>
    <p>{{.TotalCritical}} critical findings across {{.TotalTargets}} targets. Adversaries recording this traffic today will be able to decrypt it when quantum computers arrive.</p>
    <ul>
      <li>Trade secrets and intellectual property</li>
      <li>Health records (HIPAA: 50+ year retention)</li>
      <li>Financial records and transactions</li>
      <li>Internal communications and strategic plans</li>
    </ul>
  </div>
  {{end}}

  <div class="footer">
    <p>Generated by pqscan v{{.Version}}</p>
    <p><a href="https://github.com/yourorg/pqscan">github.com/yourorg/pqscan</a></p>
    <p style="margin-top: 1rem; font-style: italic; color: var(--text-dim);">
      "The largest cryptographic migration in history starts with knowing what you have."
    </p>
    <a href="https://yourproduct.com" class="cta-button">Get Automated Migration →</a>
  </div>
</div>

<script>
// All target cards start collapsed — click to expand
</script>

</body>
</html>`