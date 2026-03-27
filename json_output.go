package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

type JSONReport struct {
	Tool       string        `json:"tool"`
	Version    string        `json:"version"`
	ScanTime   string        `json:"scan_time"`
	Target     string        `json:"target"`
	Summary    JSONSummary   `json:"summary"`
	Findings   []JSONFinding `json:"findings"`
	Compliance JSONCompliance `json:"cnsa_compliance"`
}

type JSONSummary struct {
	TotalEndpoints  int     `json:"total_endpoints"`
	Vulnerable      int     `json:"vulnerable"`
	Critical        int     `json:"critical"`
	High            int     `json:"high"`
	Moderate        int     `json:"moderate"`
	Safe            int     `json:"safe"`
	RiskScore       float64 `json:"risk_score"`
	RiskLevel       string  `json:"risk_level"`
	VulnerablePct   float64 `json:"vulnerable_percentage"`
}

type JSONFinding struct {
	Host          string       `json:"host"`
	Port          int          `json:"port"`
	Service       string       `json:"service"`
	Protocol      string       `json:"protocol"`
	CipherSuite   string       `json:"cipher_suite"`
	KeyExchange   string       `json:"key_exchange"`
	RiskLevel     string       `json:"risk_level"`
	QuantumThreat string       `json:"quantum_threat"`
	Remediation   string       `json:"remediation"`
	Certificate   *JSONCert    `json:"certificate,omitempty"`
	Error         string       `json:"error,omitempty"`
}

type JSONCert struct {
	Subject      string   `json:"subject"`
	Issuer       string   `json:"issuer"`
	KeyAlgorithm string   `json:"key_algorithm"`
	KeySize      int      `json:"key_size,omitempty"`
	SignatureAlg string   `json:"signature_algorithm"`
	NotAfter     string   `json:"not_after"`
	QuantumRisk  string   `json:"quantum_risk"`
	SANs         []string `json:"sans,omitempty"`
}

type JSONCompliance struct {
	Year2025 string `json:"2025"`
	Year2027 string `json:"2027"`
	Year2030 string `json:"2030"`
	Year2033 string `json:"2033"`
	Year2035 string `json:"2035"`
}

func PrintJSONReport(target string, results []ScanResult, outputFile string) error {
	// Calculate summary
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
	}

	// Build findings
	var findings []JSONFinding
	for _, r := range results {
		f := JSONFinding{
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
			f.Certificate = &JSONCert{
				Subject:      r.Certificate.Subject,
				Issuer:       r.Certificate.Issuer,
				KeyAlgorithm: r.Certificate.KeyAlgorithm,
				KeySize:      r.Certificate.KeySize,
				SignatureAlg: r.Certificate.SignatureAlg,
				NotAfter:     r.Certificate.NotAfter.Format("2006-01-02"),
				QuantumRisk:  classifyCertRisk(r.Certificate.KeyAlgorithm),
				SANs:         r.Certificate.SANs,
			}
		}

		findings = append(findings, f)
	}

	// Compliance
	complianceStatus := "FAILING"
	if critical == 0 && high == 0 {
		complianceStatus = "PASSING"
	}

	report := JSONReport{
		Tool:     "pqscan",
		Version:  "0.1.0",
		ScanTime: time.Now().UTC().Format(time.RFC3339),
		Target:   target,
		Summary: JSONSummary{
			TotalEndpoints: total,
			Vulnerable:     vulnerable,
			Critical:       critical,
			High:           high,
			Moderate:       moderate,
			Safe:           safe,
			RiskScore:      pct,
			RiskLevel:      riskLevel,
			VulnerablePct:  pct,
		},
		Findings: findings,
		Compliance: JSONCompliance{
			Year2025: complianceStatus,
			Year2027: complianceStatus,
			Year2030: complianceStatus,
			Year2033: complianceStatus,
			Year2035: complianceStatus,
		},
	}

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return fmt.Errorf("JSON marshaling failed: %w", err)
	}

	if outputFile != "" {
		err = os.WriteFile(outputFile, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write file: %w", err)
		}
		fmt.Printf("Report written to %s\n", outputFile)
	} else {
		fmt.Println(string(data))
	}

	return nil
}