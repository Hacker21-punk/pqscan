package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fatih/color"
)

// CertChainResult holds the full certificate chain analysis
type CertChainResult struct {
	Host          string
	Port          int
	Certificates  []CertDetail
	ChainValid    bool
	ChainComplete bool
	ChainRisk     string
	ChainRiskClass string
	HasPQC        bool
	HasHybrid     bool
	Warnings      []string
}

// CertDetail holds detailed info about a single certificate
type CertDetail struct {
	Position       string // "LEAF", "INTERMEDIATE", "ROOT"
	Subject        string
	CommonName     string
	Issuer         string
	IssuerCN       string
	SerialNumber   string

	// Key information
	KeyAlgorithm   string
	KeySize        int
	KeyCurve       string
	KeyRisk        string
	KeyRiskClass   string

	// Signature information
	SignatureAlg   string
	SignatureHash  string
	SigRisk        string
	SigRiskClass   string

	// Validity
	NotBefore      time.Time
	NotAfter       time.Time
	DaysLeft       int
	ValidityYears  float64
	IsExpired      bool
	IsNotYetValid  bool

	// SANs
	DNSNames       []string
	IPAddresses    []string
	EmailAddresses []string

	// Extensions
	IsCA           bool
	KeyUsage       []string
	ExtKeyUsage    []string
	IsSelfSigned   bool

	// OCSP and CRL
	OCSPServers    []string
	CRLDistPoints  []string

	// PQC detection
	IsPQC          bool
	IsHybrid       bool
	PQCAlgorithm   string

	// Overall
	OverallRisk    string
	OverallRiskClass string
	Warnings       []string
}

// AnalyzeCertificateChain performs deep analysis of the TLS certificate chain
func AnalyzeCertificateChain(host string, port int) (*CertChainResult, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// Connect and get the full chain
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	if err != nil {
		return nil, fmt.Errorf("TLS connection failed: %w", err)
	}
	defer conn.Close()

	state := conn.ConnectionState()

	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certificates returned by server")
	}

	result := &CertChainResult{
		Host:          host,
		Port:          port,
		ChainComplete: len(state.PeerCertificates) > 1,
	}

	// Analyze each certificate in the chain
	for i, cert := range state.PeerCertificates {
		position := "INTERMEDIATE"
		if i == 0 {
			position = "LEAF"
		}
		if cert.IsCA && i == len(state.PeerCertificates)-1 {
			position = "ROOT"
		}
		// Single cert is both leaf and self-signed potentially
		if len(state.PeerCertificates) == 1 {
			position = "LEAF"
		}

		detail := analyzeSingleCert(cert, position)
		result.Certificates = append(result.Certificates, detail)

		// Track PQC status
		if detail.IsPQC {
			result.HasPQC = true
		}
		if detail.IsHybrid {
			result.HasHybrid = true
		}
	}

	// Check if we should try to verify the chain
	verifyConn, verifyErr := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	if verifyErr == nil {
		result.ChainValid = true
		verifyConn.Close()
	} else {
		result.ChainValid = false
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Certificate verification failed: %v", verifyErr))
	}

	// Determine chain risk (worst of any cert in chain)
	result.ChainRisk = "SAFE"
	result.ChainRiskClass = "safe"

	for _, cert := range result.Certificates {
		if cert.OverallRisk == "CRITICAL" {
			result.ChainRisk = "CRITICAL"
			result.ChainRiskClass = "critical"
			break
		} else if cert.OverallRisk == "HIGH" && result.ChainRisk != "CRITICAL" {
			result.ChainRisk = "HIGH"
			result.ChainRiskClass = "high"
		} else if cert.OverallRisk == "MODERATE" && result.ChainRisk == "SAFE" {
			result.ChainRisk = "MODERATE"
			result.ChainRiskClass = "moderate"
		}
	}

	// Chain-level warnings
	if !result.ChainComplete {
		result.Warnings = append(result.Warnings,
			"Incomplete chain — server did not send intermediate certificates")
	}

	if len(result.Certificates) == 1 && result.Certificates[0].IsSelfSigned {
		result.Warnings = append(result.Warnings,
			"Self-signed certificate — not trusted by default")
	}

	// Check for mixed algorithms in chain
	algorithms := make(map[string]bool)
	for _, cert := range result.Certificates {
		algorithms[cert.KeyAlgorithm] = true
	}
	if len(algorithms) > 1 {
		var algs []string
		for a := range algorithms {
			algs = append(algs, a)
		}
		result.Warnings = append(result.Warnings,
			fmt.Sprintf("Mixed key algorithms in chain: %s", strings.Join(algs, ", ")))
	}

	return result, nil
}

// analyzeSingleCert extracts all information from a single certificate
func analyzeSingleCert(cert *x509.Certificate, position string) CertDetail {
	detail := CertDetail{
		Position:       position,
		Subject:        cert.Subject.String(),
		CommonName:     cert.Subject.CommonName,
		Issuer:         cert.Issuer.String(),
		IssuerCN:       cert.Issuer.CommonName,
		SerialNumber:   cert.SerialNumber.String(),
		NotBefore:      cert.NotBefore,
		NotAfter:       cert.NotAfter,
		IsCA:           cert.IsCA,
		DNSNames:       cert.DNSNames,
		EmailAddresses: cert.EmailAddresses,
		OCSPServers:    cert.OCSPServer,
		CRLDistPoints:  cert.CRLDistributionPoints,
	}

	// Calculate validity
	detail.DaysLeft = int(time.Until(cert.NotAfter).Hours() / 24)
	detail.ValidityYears = cert.NotAfter.Sub(cert.NotBefore).Hours() / 24 / 365.25
	detail.IsExpired = time.Now().After(cert.NotAfter)
	detail.IsNotYetValid = time.Now().Before(cert.NotBefore)

	// Check self-signed
	detail.IsSelfSigned = cert.Subject.String() == cert.Issuer.String()

	// IP addresses
	for _, ip := range cert.IPAddresses {
		detail.IPAddresses = append(detail.IPAddresses, ip.String())
	}

	// Key Usage
	detail.KeyUsage = parseKeyUsage(cert.KeyUsage)
	detail.ExtKeyUsage = parseExtKeyUsage(cert.ExtKeyUsage)

	// Analyze public key
	analyzePublicKey(cert, &detail)

	// Analyze signature algorithm
	analyzeSignatureAlgorithm(cert, &detail)

	// Detect PQC / hybrid
	detectPQC(cert, &detail)

	// Determine overall risk (worst of key risk and sig risk)
	detail.OverallRisk = worstRisk(detail.KeyRisk, detail.SigRisk)
	detail.OverallRiskClass = riskToClass(detail.OverallRisk)

	// Add warnings
	if detail.IsExpired {
		detail.Warnings = append(detail.Warnings, "Certificate has EXPIRED")
	}
	if detail.IsNotYetValid {
		detail.Warnings = append(detail.Warnings, "Certificate is not yet valid")
	}
	if detail.DaysLeft > 0 && detail.DaysLeft < 30 {
		detail.Warnings = append(detail.Warnings,
			fmt.Sprintf("Certificate expires in %d days", detail.DaysLeft))
	}
	if detail.ValidityYears > 5 && position == "LEAF" {
		detail.Warnings = append(detail.Warnings,
			fmt.Sprintf("Very long validity period (%.1f years) — increased HNDL risk", detail.ValidityYears))
	}
	if detail.KeySize > 0 && detail.KeySize < 2048 && strings.Contains(detail.KeyAlgorithm, "RSA") {
		detail.Warnings = append(detail.Warnings,
			"RSA key size < 2048 bits — broken even classically")
	}
	if strings.Contains(detail.SignatureHash, "SHA-1") || strings.Contains(detail.SignatureHash, "SHA1") {
		detail.Warnings = append(detail.Warnings,
			"SHA-1 signature — broken classically, insecure")
	}
	if strings.Contains(detail.SignatureHash, "MD5") {
		detail.Warnings = append(detail.Warnings,
			"MD5 signature — completely broken, critically insecure")
	}

	return detail
}

// analyzePublicKey extracts key algorithm, size, and quantum risk
func analyzePublicKey(cert *x509.Certificate, detail *CertDetail) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		detail.KeyAlgorithm = "RSA"
		detail.KeySize = pub.N.BitLen()
		detail.KeyRisk = "CRITICAL"
		detail.KeyRiskClass = "critical"

	case *ecdsa.PublicKey:
		detail.KeyAlgorithm = "ECDSA"
		detail.KeyCurve = pub.Curve.Params().Name
		detail.KeySize = pub.Curve.Params().BitSize

		// Map curve names
		switch pub.Curve {
		case elliptic.P224():
			detail.KeyCurve = "P-224"
		case elliptic.P256():
			detail.KeyCurve = "P-256"
		case elliptic.P384():
			detail.KeyCurve = "P-384"
		case elliptic.P521():
			detail.KeyCurve = "P-521"
		}

		detail.KeyAlgorithm = fmt.Sprintf("ECDSA %s", detail.KeyCurve)
		detail.KeyRisk = "CRITICAL"
		detail.KeyRiskClass = "critical"

	case ed25519.PublicKey:
		detail.KeyAlgorithm = "Ed25519"
		detail.KeySize = 256
		detail.KeyRisk = "CRITICAL"
		detail.KeyRiskClass = "critical"

	default:
		// Check for PQC algorithms by OID
		oid := cert.PublicKeyAlgorithm.String()

		if isPQCAlgorithm(oid) {
			detail.KeyAlgorithm = mapPQCOID(oid)
			detail.KeyRisk = "SAFE"
			detail.KeyRiskClass = "safe"
			detail.IsPQC = true
		} else {
			detail.KeyAlgorithm = fmt.Sprintf("Unknown (%s)", oid)
			detail.KeyRisk = "UNKNOWN"
			detail.KeyRiskClass = "moderate"
		}

		_ = pub
	}
}

// analyzeSignatureAlgorithm determines the signature algorithm and its risk
func analyzeSignatureAlgorithm(cert *x509.Certificate, detail *CertDetail) {
	sigAlg := cert.SignatureAlgorithm.String()
	detail.SignatureAlg = sigAlg

	switch cert.SignatureAlgorithm {
	// MD5 based (classically broken)
	case x509.MD5WithRSA:
		detail.SignatureHash = "MD5"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	// SHA1 based (classically broken)
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1, x509.DSAWithSHA1:
		detail.SignatureHash = "SHA-1"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	// SHA256 based with RSA/ECDSA (quantum vulnerable)
	case x509.SHA256WithRSA, x509.SHA256WithRSAPSS:
		detail.SignatureHash = "SHA-256"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	case x509.ECDSAWithSHA256:
		detail.SignatureHash = "SHA-256"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	// SHA384 based
	case x509.SHA384WithRSA, x509.SHA384WithRSAPSS:
		detail.SignatureHash = "SHA-384"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	case x509.ECDSAWithSHA384:
		detail.SignatureHash = "SHA-384"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	// SHA512 based
	case x509.SHA512WithRSA, x509.SHA512WithRSAPSS:
		detail.SignatureHash = "SHA-512"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	case x509.ECDSAWithSHA512:
		detail.SignatureHash = "SHA-512"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	case x509.PureEd25519:
		detail.SignatureHash = "Ed25519 (built-in)"
		detail.SigRisk = "CRITICAL"
		detail.SigRiskClass = "critical"

	default:
		// Check for PQC signature OIDs
		if isPQCSignatureAlgorithm(sigAlg) {
			detail.SignatureHash = "PQC"
			detail.SigRisk = "SAFE"
			detail.SigRiskClass = "safe"
			detail.IsPQC = true
		} else {
			detail.SignatureHash = "Unknown"
			detail.SigRisk = "UNKNOWN"
			detail.SigRiskClass = "moderate"
		}
	}
}

// detectPQC checks for PQC or hybrid certificates
func detectPQC(cert *x509.Certificate, detail *CertDetail) {
	// Check OIDs in extensions for PQC indicators
	for _, ext := range cert.Extensions {
		oid := ext.Id.String()

		// Known PQC-related OIDs
		pqcOIDs := map[string]string{
			// ML-DSA (Dilithium) OIDs
			"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
			"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
			"2.16.840.1.101.3.4.3.19": "ML-DSA-87",

			// Composite signature OIDs
			"2.16.840.1.114027.80.8.1.1":  "MLDSA44-RSA2048-PSS-SHA256",
			"2.16.840.1.114027.80.8.1.2":  "MLDSA44-RSA2048-PKCS15-SHA256",
			"2.16.840.1.114027.80.8.1.3":  "MLDSA44-Ed25519-SHA512",
			"2.16.840.1.114027.80.8.1.4":  "MLDSA44-ECDSA-P256-SHA256",
			"2.16.840.1.114027.80.8.1.5":  "MLDSA65-RSA3072-PSS-SHA512",
			"2.16.840.1.114027.80.8.1.6":  "MLDSA65-ECDSA-P256-SHA512",
			"2.16.840.1.114027.80.8.1.7":  "MLDSA65-Ed25519-SHA512",
			"2.16.840.1.114027.80.8.1.8":  "MLDSA87-ECDSA-P384-SHA512",
			"2.16.840.1.114027.80.8.1.9":  "MLDSA87-Ed448-SHA512",

			// SLH-DSA (SPHINCS+) OIDs
			"2.16.840.1.101.3.4.3.20": "SLH-DSA-SHA2-128s",
			"2.16.840.1.101.3.4.3.21": "SLH-DSA-SHA2-128f",
			"2.16.840.1.101.3.4.3.22": "SLH-DSA-SHA2-192s",
			"2.16.840.1.101.3.4.3.23": "SLH-DSA-SHA2-192f",
			"2.16.840.1.101.3.4.3.24": "SLH-DSA-SHA2-256s",
			"2.16.840.1.101.3.4.3.25": "SLH-DSA-SHA2-256f",
		}

		if name, ok := pqcOIDs[oid]; ok {
			detail.IsPQC = true
			detail.PQCAlgorithm = name
			detail.KeyRisk = "SAFE"
			detail.KeyRiskClass = "safe"
			detail.SigRisk = "SAFE"
			detail.SigRiskClass = "safe"

			if strings.Contains(name, "-RSA") || strings.Contains(name, "-ECDSA") ||
				strings.Contains(name, "-Ed25519") || strings.Contains(name, "-Ed448") {
				detail.IsHybrid = true
			}
		}
	}

	// Also check the signature algorithm string for PQC indicators
	sigStr := strings.ToLower(cert.SignatureAlgorithm.String())
	if strings.Contains(sigStr, "dilithium") || strings.Contains(sigStr, "ml-dsa") ||
		strings.Contains(sigStr, "sphincs") || strings.Contains(sigStr, "slh-dsa") ||
		strings.Contains(sigStr, "falcon") || strings.Contains(sigStr, "fn-dsa") {
		detail.IsPQC = true
		detail.PQCAlgorithm = cert.SignatureAlgorithm.String()
		detail.SigRisk = "SAFE"
		detail.SigRiskClass = "safe"
	}
}

func isPQCAlgorithm(oid string) bool {
	pqcOIDs := []string{
		"2.16.840.1.101.3.4.4",   // ML-KEM family
		"2.16.840.1.101.3.4.3.17", // ML-DSA-44
		"2.16.840.1.101.3.4.3.18", // ML-DSA-65
		"2.16.840.1.101.3.4.3.19", // ML-DSA-87
	}
	for _, p := range pqcOIDs {
		if strings.HasPrefix(oid, p) {
			return true
		}
	}
	return false
}

func isPQCSignatureAlgorithm(sigAlg string) bool {
	lower := strings.ToLower(sigAlg)
	pqcKeywords := []string{
		"dilithium", "ml-dsa", "mldsa",
		"sphincs", "slh-dsa", "slhdsa",
		"falcon", "fn-dsa", "fndsa",
		"xmss", "lms",
	}
	for _, kw := range pqcKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

func mapPQCOID(oid string) string {
	mapping := map[string]string{
		"2.16.840.1.101.3.4.3.17": "ML-DSA-44",
		"2.16.840.1.101.3.4.3.18": "ML-DSA-65",
		"2.16.840.1.101.3.4.3.19": "ML-DSA-87",
	}
	if name, ok := mapping[oid]; ok {
		return name
	}
	return "PQC (" + oid + ")"
}

func parseKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	if ku&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if ku&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if ku&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if ku&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if ku&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Signing")
	}
	if ku&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Signing")
	}
	if ku&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	return usages
}

func parseExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	var usages []string
	for _, u := range eku {
		switch u {
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection (S/MIME)")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Timestamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		}
	}
	return usages
}

func worstRisk(risks ...string) string {
	priority := map[string]int{
		"CRITICAL": 100,
		"HIGH":     75,
		"MODERATE": 50,
		"UNKNOWN":  40,
		"LOW":      25,
		"SAFE":     0,
	}
	worst := "SAFE"
	worstPri := 0
	for _, r := range risks {
		if p, ok := priority[r]; ok && p > worstPri {
			worst = r
			worstPri = p
		}
	}
	return worst
}

func riskToClass(risk string) string {
	switch risk {
	case "CRITICAL":
		return "critical"
	case "HIGH":
		return "high"
	case "MODERATE":
		return "moderate"
	case "SAFE":
		return "safe"
	default:
		return "moderate"
	}
}

// PrintCertChainReport prints the certificate chain analysis to terminal
func PrintCertChainReport(chain *CertChainResult) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	cyan := color.New(color.FgCyan)
	dim := color.New(color.FgWhite)

	fmt.Println()
	white.Printf(" 📜 CERTIFICATE CHAIN — %s:%d\n", chain.Host, chain.Port)
	fmt.Println(" " + strings.Repeat("─", 55))

	for i, cert := range chain.Certificates {
		fmt.Println()

		// Position indicator
		connector := " ├"
		if i == len(chain.Certificates)-1 {
			connector = " └"
		}

		// Risk icon
		icon := "🔴"
		riskColor := red
		switch cert.OverallRisk {
		case "SAFE":
			icon = "🟢"
			riskColor = green
		case "MODERATE", "UNKNOWN":
			icon = "🟡"
			riskColor = yellow
		case "HIGH":
			icon = "🟠"
			riskColor = yellow
		}

		riskColor.Printf("%s─ %s %s: %s\n", connector, icon, cert.Position, cert.CommonName)

		indent := " │  "
		if i == len(chain.Certificates)-1 {
			indent = "    "
		}

		// Key info
		keyInfo := cert.KeyAlgorithm
		if cert.KeySize > 0 {
			keyInfo = fmt.Sprintf("%s (%d-bit)", cert.KeyAlgorithm, cert.KeySize)
		}
		cyan.Printf("%sKey:       %s\n", indent, keyInfo)

		// Key risk
		switch cert.KeyRiskClass {
		case "critical":
			red.Printf("%sKey Risk:  %s — Broken by Shor's algorithm\n", indent, cert.KeyRisk)
		case "safe":
			green.Printf("%sKey Risk:  %s — Post-quantum safe\n", indent, cert.KeyRisk)
		default:
			yellow.Printf("%sKey Risk:  %s\n", indent, cert.KeyRisk)
		}

		// Signature info
		cyan.Printf("%sSignature: %s (%s)\n", indent, cert.SignatureAlg, cert.SignatureHash)

		// Signature risk
		switch cert.SigRiskClass {
		case "critical":
			red.Printf("%sSig Risk:  %s — Signature forgeable by quantum\n", indent, cert.SigRisk)
		case "safe":
			green.Printf("%sSig Risk:  %s — Post-quantum safe\n", indent, cert.SigRisk)
		default:
			yellow.Printf("%sSig Risk:  %s\n", indent, cert.SigRisk)
		}

		// Validity
		if cert.IsExpired {
			red.Printf("%sExpires:   %s (EXPIRED!)\n", indent,
				cert.NotAfter.Format("2006-01-02"))
		} else if cert.DaysLeft < 30 {
			yellow.Printf("%sExpires:   %s (%d days!)\n", indent,
				cert.NotAfter.Format("2006-01-02"), cert.DaysLeft)
		} else {
			dim.Printf("%sExpires:   %s (%d days)\n", indent,
				cert.NotAfter.Format("2006-01-02"), cert.DaysLeft)
		}

		// Validity period
		dim.Printf("%sValidity:  %.1f years\n", indent, cert.ValidityYears)

		// Self-signed indicator
		if cert.IsSelfSigned {
			dim.Printf("%sType:      Self-signed\n", indent)
		}

		// CA status
		if cert.IsCA {
			dim.Printf("%sCA:        Yes\n", indent)
		}

		// Key usage
		if len(cert.KeyUsage) > 0 {
			dim.Printf("%sUsage:     %s\n", indent, strings.Join(cert.KeyUsage, ", "))
		}

		// Extended key usage
		if len(cert.ExtKeyUsage) > 0 {
			dim.Printf("%sExt Usage: %s\n", indent, strings.Join(cert.ExtKeyUsage, ", "))
		}

		// SANs (show first few)
		if len(cert.DNSNames) > 0 {
			if len(cert.DNSNames) <= 3 {
				dim.Printf("%sSANs:      %s\n", indent, strings.Join(cert.DNSNames, ", "))
			} else {
				dim.Printf("%sSANs:      %s (+%d more)\n", indent,
					strings.Join(cert.DNSNames[:3], ", "), len(cert.DNSNames)-3)
			}
		}

		// PQC status
		if cert.IsPQC {
			green.Printf("%sPQC:       ✅ %s\n", indent, cert.PQCAlgorithm)
		}
		if cert.IsHybrid {
			green.Printf("%sHybrid:    ✅ Composite classical + PQC\n", indent)
		}

		// OCSP
		if len(cert.OCSPServers) > 0 {
			dim.Printf("%sOCSP:      %s\n", indent, cert.OCSPServers[0])
		}

		// Warnings
		for _, w := range cert.Warnings {
			yellow.Printf("%s⚠ %s\n", indent, w)
		}
	}

	// Chain verdict
	fmt.Println()
	fmt.Println(" " + strings.Repeat("─", 55))

	switch chain.ChainRisk {
	case "CRITICAL":
		red.Println(" ⛓ CHAIN VERDICT: CRITICAL")
		red.Println("   If ANY certificate in the chain uses quantum-vulnerable")
		red.Println("   algorithms, the ENTIRE chain can be compromised.")
		red.Println("   An attacker with a quantum computer could forge certificates")
		red.Println("   or impersonate any server in this chain.")
	case "SAFE":
		green.Println(" ⛓ CHAIN VERDICT: QUANTUM SAFE ✅")
		green.Println("   All certificates in the chain use post-quantum algorithms.")
	default:
		yellow.Printf(" ⛓ CHAIN VERDICT: %s\n", chain.ChainRisk)
	}

	// PQC hybrid detection
	fmt.Println()
	if chain.HasPQC || chain.HasHybrid {
		green.Println(" 🔬 PQC STATUS: Detected")
		if chain.HasHybrid {
			green.Println("   Hybrid (composite) PQC certificates found.")
			green.Println("   This chain uses both classical and post-quantum algorithms.")
		} else {
			green.Println("   Pure PQC certificates detected in chain.")
		}
	} else {
		yellow.Println(" 🔬 PQC STATUS: Not detected")
		yellow.Println("   No post-quantum or hybrid certificates found.")
		yellow.Println("   Migration to PQC certificates is recommended.")
		fmt.Println()
		cyan.Println("   Recommended actions:")
		cyan.Println("   1. Contact your CA about PQC certificate availability")
		cyan.Println("   2. Consider hybrid certificates (classical + PQC)")
		cyan.Println("   3. Test with PQC certificates in staging environment")
		cyan.Println("   4. Plan full migration before CNSA 2.0 deadline (2033)")
	}

	// Chain-level warnings
	if len(chain.Warnings) > 0 {
		fmt.Println()
		yellow.Println(" ⚠ CHAIN WARNINGS:")
		for _, w := range chain.Warnings {
			yellow.Printf("   • %s\n", w)
		}
	}

	fmt.Println()
}