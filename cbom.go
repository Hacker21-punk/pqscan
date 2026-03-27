package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

// CycloneDX CBOM structures (spec 1.6)
type CycloneDXBOM struct {
	BOMFormat    string            `json:"bomFormat"`
	SpecVersion  string            `json:"specVersion"`
	SerialNumber string            `json:"serialNumber"`
	Version      int               `json:"version"`
	Metadata     CBOMMetadata      `json:"metadata"`
	Components   []CBOMComponent   `json:"components"`
	Dependencies []CBOMDependency  `json:"dependencies,omitempty"`
	Compositions []CBOMComposition `json:"compositions,omitempty"`
}

type CBOMMetadata struct {
	Timestamp string       `json:"timestamp"`
	Tools     []CBOMTool   `json:"tools"`
	Component *CBOMTarget  `json:"component,omitempty"`
	Properties []CBOMProperty `json:"properties,omitempty"`
}

type CBOMTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CBOMTarget struct {
	Type string `json:"type"`
	Name string `json:"name"`
}

type CBOMComponent struct {
	Type             string            `json:"type"`
	BOMRef           string            `json:"bom-ref"`
	Name             string            `json:"name"`
	Version          string            `json:"version,omitempty"`
	Description      string            `json:"description,omitempty"`
	CryptoProperties *CryptoProperties `json:"cryptoProperties,omitempty"`
	Evidence         *CBOMEvidence     `json:"evidence,omitempty"`
	Properties       []CBOMProperty    `json:"properties,omitempty"`
}

type CryptoProperties struct {
	AssetType           string               `json:"assetType"`
	AlgorithmProperties *AlgorithmProperties `json:"algorithmProperties,omitempty"`
	ProtocolProperties  *ProtocolProperties  `json:"protocolProperties,omitempty"`
	CertificateProperties *CertificateProps  `json:"certificateProperties,omitempty"`
	OID                 string               `json:"oid,omitempty"`
}

type AlgorithmProperties struct {
	Primitive             string `json:"primitive,omitempty"`
	ParameterSetIdentifier string `json:"parameterSetIdentifier,omitempty"`
	Curve                 string `json:"curve,omitempty"`
	ExecutionEnvironment  string `json:"executionEnvironment,omitempty"`
	ImplementationPlatform string `json:"implementationPlatform,omitempty"`
	CryptoFunctions       []string `json:"cryptoFunctions,omitempty"`
	ClassicalSecurityLevel int    `json:"classicalSecurityLevel,omitempty"`
	NistQuantumSecurityLevel int  `json:"nistQuantumSecurityLevel,omitempty"`
}

type ProtocolProperties struct {
	Type            string           `json:"type,omitempty"`
	Version         string           `json:"version,omitempty"`
	CipherSuites    []CipherSuiteRef `json:"cipherSuites,omitempty"`
}

type CipherSuiteRef struct {
	Name        string   `json:"name"`
	Algorithms  []string `json:"algorithms,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
}

type CertificateProps struct {
	SubjectName          string `json:"subjectName,omitempty"`
	IssuerName           string `json:"issuerName,omitempty"`
	NotValidBefore       string `json:"notValidBefore,omitempty"`
	NotValidAfter        string `json:"notValidAfter,omitempty"`
	SignatureAlgorithmRef string `json:"signatureAlgorithmRef,omitempty"`
	SubjectPublicKeyRef  string `json:"subjectPublicKeyRef,omitempty"`
}

type CBOMEvidence struct {
	Occurrences []CBOMOccurrence `json:"occurrences,omitempty"`
}

type CBOMOccurrence struct {
	Location string `json:"location"`
}

type CBOMProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CBOMDependency struct {
	Ref       string   `json:"ref"`
	DependsOn []string `json:"dependsOn,omitempty"`
}

type CBOMComposition struct {
	Aggregate  string   `json:"aggregate"`
	Assemblies []string `json:"assemblies,omitempty"`
}

// GenerateCBOM creates a CycloneDX Cryptographic Bill of Materials
func GenerateCBOM(target string, results []ScanResult, outputFile string) error {
	bom := buildCBOM(target, results)

	data, err := json.MarshalIndent(bom, "", "  ")
	if err != nil {
		return fmt.Errorf("CBOM JSON marshaling failed: %w", err)
	}

	if outputFile != "" {
		err = os.WriteFile(outputFile, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write CBOM: %w", err)
		}
		fmt.Printf("  CBOM written to: %s\n", outputFile)
		fmt.Printf("  Format: CycloneDX v1.6 (Cryptographic BOM)\n")
		fmt.Printf("  Components: %d cryptographic assets\n", len(bom.Components))
	} else {
		fmt.Println(string(data))
	}

	return nil
}

func buildCBOM(target string, results []ScanResult) CycloneDXBOM {
	bomUUID := uuid.New().String()

	bom := CycloneDXBOM{
		BOMFormat:    "CycloneDX",
		SpecVersion:  "1.6",
		SerialNumber: fmt.Sprintf("urn:uuid:%s", bomUUID),
		Version:      1,
		Metadata: CBOMMetadata{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Tools: []CBOMTool{
				{
					Vendor:  "pqscan",
					Name:    "pqscan",
					Version: "0.1.0",
				},
			},
			Component: &CBOMTarget{
				Type: "application",
				Name: target,
			},
			Properties: []CBOMProperty{
				{Name: "pqscan:scan-target", Value: target},
				{Name: "pqscan:scan-type", Value: "quantum-vulnerability-assessment"},
				{Name: "pqscan:total-endpoints", Value: fmt.Sprintf("%d", len(results))},
			},
		},
	}

	var components []CBOMComponent
	var dependencies []CBOMDependency
	componentRefs := make(map[string]bool)

	for _, r := range results {
		endpointRef := fmt.Sprintf("endpoint-%s-%d", r.Host, r.Port)

		// 1. Protocol component
		protocolRef := fmt.Sprintf("protocol-%s-%d-%s", r.Host, r.Port, sanitizeRef(r.Protocol))
		if !componentRefs[protocolRef] {
			componentRefs[protocolRef] = true
			components = append(components, buildProtocolComponent(protocolRef, r))
		}

		// 2. Cipher suite component
		cipherRef := fmt.Sprintf("cipher-%s", sanitizeRef(r.CipherSuite))
		if !componentRefs[cipherRef] {
			componentRefs[cipherRef] = true
			components = append(components, buildCipherSuiteComponent(cipherRef, r))
		}

		// 3. Key exchange component
		kexRef := fmt.Sprintf("kex-%s-%d", sanitizeRef(r.KeyExchange), r.Port)
		if !componentRefs[kexRef] {
			componentRefs[kexRef] = true
			components = append(components, buildKeyExchangeComponent(kexRef, r))
		}

		// 4. Certificate components
		if r.Certificate.Subject != "" {
			certRef := fmt.Sprintf("cert-%s-%d", r.Host, r.Port)
			if !componentRefs[certRef] {
				componentRefs[certRef] = true
				components = append(components, buildCertificateComponent(certRef, r))
			}

			// Certificate public key
			certKeyRef := fmt.Sprintf("certkey-%s-%d", r.Host, r.Port)
			if !componentRefs[certKeyRef] {
				componentRefs[certKeyRef] = true
				components = append(components, buildCertKeyComponent(certKeyRef, r))
			}

			// Certificate signature algorithm
			certSigRef := fmt.Sprintf("certsig-%s-%d", r.Host, r.Port)
			if !componentRefs[certSigRef] {
				componentRefs[certSigRef] = true
				components = append(components, buildCertSigComponent(certSigRef, r))
			}

			// Dependencies: cert depends on key and sig
			dependencies = append(dependencies, CBOMDependency{
				Ref:       certRef,
				DependsOn: []string{certKeyRef, certSigRef},
			})
		}

		// Endpoint depends on protocol, cipher, kex
		depRefs := []string{protocolRef, cipherRef, kexRef}
		if r.Certificate.Subject != "" {
			depRefs = append(depRefs, fmt.Sprintf("cert-%s-%d", r.Host, r.Port))
		}

		dependencies = append(dependencies, CBOMDependency{
			Ref:       endpointRef,
			DependsOn: depRefs,
		})
	}

	bom.Components = components
	bom.Dependencies = dependencies

	// Add composition info
	var allRefs []string
	for ref := range componentRefs {
		allRefs = append(allRefs, ref)
	}
	bom.Compositions = []CBOMComposition{
		{
			Aggregate:  "complete",
			Assemblies: allRefs,
		},
	}

	return bom
}

func buildProtocolComponent(ref string, r ScanResult) CBOMComponent {
	quantumStatus := "vulnerable"
	if r.RiskLevel == "SAFE" {
		quantumStatus = "safe"
	}

	return CBOMComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        r.Protocol,
		Description: fmt.Sprintf("%s protocol on %s:%d (%s)", r.Protocol, r.Host, r.Port, r.Service),
		CryptoProperties: &CryptoProperties{
			AssetType: "protocol",
			ProtocolProperties: &ProtocolProperties{
				Type:    getProtocolType(r.Service),
				Version: r.Protocol,
				CipherSuites: []CipherSuiteRef{
					{
						Name:       r.CipherSuite,
						Algorithms: extractAlgorithmsFromSuite(r.CipherSuite),
					},
				},
			},
		},
		Evidence: &CBOMEvidence{
			Occurrences: []CBOMOccurrence{
				{Location: fmt.Sprintf("%s:%d", r.Host, r.Port)},
			},
		},
		Properties: []CBOMProperty{
			{Name: "pqscan:service", Value: r.Service},
			{Name: "pqscan:risk-level", Value: r.RiskLevel},
			{Name: "pqscan:quantum-status", Value: quantumStatus},
			{Name: "pqscan:quantum-threat", Value: r.QuantumThreat},
			{Name: "pqscan:remediation", Value: r.Remediation},
		},
	}
}

func buildCipherSuiteComponent(ref string, r ScanResult) CBOMComponent {
	return CBOMComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        r.CipherSuite,
		Description: fmt.Sprintf("Cipher suite negotiated on %s:%d", r.Host, r.Port),
		CryptoProperties: &CryptoProperties{
			AssetType: "related-crypto-material",
			AlgorithmProperties: &AlgorithmProperties{
				Primitive:              "cipher",
				CryptoFunctions:        []string{"encrypt", "decrypt"},
				ExecutionEnvironment:   "server",
				ClassicalSecurityLevel: getClassicalSecurity(r.CipherSuite),
				NistQuantumSecurityLevel: getQuantumSecurity(r.CipherSuite),
			},
		},
		Properties: []CBOMProperty{
			{Name: "pqscan:risk-level", Value: r.RiskLevel},
		},
	}
}

func buildKeyExchangeComponent(ref string, r ScanResult) CBOMComponent {
	primitive := "key-agree"
	if strings.Contains(strings.ToUpper(r.KeyExchange), "RSA") {
		primitive = "key-encapsulate"
	}

	quantumStatus := "vulnerable"
	if strings.Contains(strings.ToUpper(r.KeyExchange), "ML-KEM") ||
		strings.Contains(strings.ToUpper(r.KeyExchange), "KYBER") {
		quantumStatus = "safe"
	}

	return CBOMComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        r.KeyExchange,
		Description: fmt.Sprintf("Key exchange algorithm on %s:%d", r.Host, r.Port),
		CryptoProperties: &CryptoProperties{
			AssetType: "algorithm",
			AlgorithmProperties: &AlgorithmProperties{
				Primitive:            primitive,
				CryptoFunctions:     []string{"keygen", "encapsulate", "decapsulate"},
				ExecutionEnvironment: "server",
			},
		},
		Properties: []CBOMProperty{
			{Name: "pqscan:quantum-status", Value: quantumStatus},
			{Name: "pqscan:quantum-threat", Value: r.QuantumThreat},
		},
	}
}

func buildCertificateComponent(ref string, r ScanResult) CBOMComponent {
	return CBOMComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        fmt.Sprintf("Certificate: %s", r.Certificate.Subject),
		Description: fmt.Sprintf("TLS certificate for %s", r.Host),
		CryptoProperties: &CryptoProperties{
			AssetType: "certificate",
			CertificateProperties: &CertificateProps{
				SubjectName:   r.Certificate.Subject,
				IssuerName:    r.Certificate.Issuer,
				NotValidAfter: r.Certificate.NotAfter.Format(time.RFC3339),
				SignatureAlgorithmRef: fmt.Sprintf("certsig-%s-%d", r.Host, r.Port),
				SubjectPublicKeyRef:  fmt.Sprintf("certkey-%s-%d", r.Host, r.Port),
			},
		},
		Evidence: &CBOMEvidence{
			Occurrences: []CBOMOccurrence{
				{Location: fmt.Sprintf("%s:%d", r.Host, r.Port)},
			},
		},
		Properties: []CBOMProperty{
			{Name: "pqscan:cert-subject", Value: r.Certificate.Subject},
			{Name: "pqscan:cert-issuer", Value: r.Certificate.Issuer},
			{Name: "pqscan:cert-expiry", Value: r.Certificate.NotAfter.Format("2006-01-02")},
			{Name: "pqscan:cert-risk", Value: classifyCertRisk(r.Certificate.KeyAlgorithm)},
		},
	}
}

func buildCertKeyComponent(ref string, r ScanResult) CBOMComponent {
	keyAlg := r.Certificate.KeyAlgorithm
	keySize := r.Certificate.KeySize

	primitive := "signature"
	if strings.Contains(strings.ToUpper(keyAlg), "RSA") {
		primitive = "signature"
	} else if strings.Contains(strings.ToUpper(keyAlg), "EC") ||
		strings.Contains(strings.ToUpper(keyAlg), "ED25519") {
		primitive = "signature"
	}

	quantumStatus := "vulnerable"
	if strings.Contains(strings.ToUpper(keyAlg), "ML-DSA") ||
		strings.Contains(strings.ToUpper(keyAlg), "DILITHIUM") ||
		strings.Contains(strings.ToUpper(keyAlg), "SPHINCS") ||
		strings.Contains(strings.ToUpper(keyAlg), "SLH-DSA") {
		quantumStatus = "safe"
	}

	paramSet := ""
	if keySize > 0 {
		paramSet = fmt.Sprintf("%d", keySize)
	}

	return CBOMComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        fmt.Sprintf("%s (%d-bit)", keyAlg, keySize),
		Description: fmt.Sprintf("Certificate public key for %s", r.Host),
		CryptoProperties: &CryptoProperties{
			AssetType: "algorithm",
			AlgorithmProperties: &AlgorithmProperties{
				Primitive:               primitive,
				ParameterSetIdentifier:  paramSet,
				CryptoFunctions:         []string{"sign", "verify"},
				ExecutionEnvironment:    "server",
				ClassicalSecurityLevel:  getKeyClassicalSecurity(keyAlg, keySize),
				NistQuantumSecurityLevel: 0, // broken by quantum
			},
		},
		Properties: []CBOMProperty{
			{Name: "pqscan:key-algorithm", Value: keyAlg},
			{Name: "pqscan:key-size", Value: fmt.Sprintf("%d", keySize)},
			{Name: "pqscan:quantum-status", Value: quantumStatus},
		},
	}
}

func buildCertSigComponent(ref string, r ScanResult) CBOMComponent {
	sigAlg := r.Certificate.SignatureAlg

	quantumStatus := "vulnerable"
	if strings.Contains(strings.ToUpper(sigAlg), "ML-DSA") ||
		strings.Contains(strings.ToUpper(sigAlg), "DILITHIUM") ||
		strings.Contains(strings.ToUpper(sigAlg), "SLH-DSA") {
		quantumStatus = "safe"
	}

	return CBOMComponent{
		Type:        "cryptographic-asset",
		BOMRef:      ref,
		Name:        sigAlg,
		Description: fmt.Sprintf("Certificate signature algorithm for %s", r.Host),
		CryptoProperties: &CryptoProperties{
			AssetType: "algorithm",
			AlgorithmProperties: &AlgorithmProperties{
				Primitive:        "signature",
				CryptoFunctions:  []string{"sign", "verify"},
				ExecutionEnvironment: "server",
			},
		},
		Properties: []CBOMProperty{
			{Name: "pqscan:signature-algorithm", Value: sigAlg},
			{Name: "pqscan:quantum-status", Value: quantumStatus},
		},
	}
}

// Helper functions

func sanitizeRef(s string) string {
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "-")
	s = strings.ReplaceAll(s, "(", "")
	s = strings.ReplaceAll(s, ")", "")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ".", "-")
	s = strings.ReplaceAll(s, ",", "")
	s = strings.ReplaceAll(s, "'", "")
	s = strings.ReplaceAll(s, "\"", "")
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

func getProtocolType(service string) string {
	switch strings.ToUpper(service) {
	case "HTTPS", "HTTPS-ALT":
		return "tls"
	case "SSH", "SSH-ALT":
		return "ssh"
	case "SMTP", "SMTP-SUBMISSION", "SMTPS":
		return "tls"
	case "IMAPS", "IMAP":
		return "tls"
	case "POP3S", "POP3":
		return "tls"
	default:
		return "tls"
	}
}

func extractAlgorithmsFromSuite(suite string) []string {
	var algs []string
	upper := strings.ToUpper(suite)

	// Key exchange
	if strings.Contains(upper, "ECDHE") {
		algs = append(algs, "ECDHE")
	} else if strings.Contains(upper, "DHE") {
		algs = append(algs, "DHE")
	} else if strings.Contains(upper, "RSA") {
		algs = append(algs, "RSA")
	}

	// Symmetric cipher
	if strings.Contains(upper, "AES_256_GCM") {
		algs = append(algs, "AES-256-GCM")
	} else if strings.Contains(upper, "AES_128_GCM") {
		algs = append(algs, "AES-128-GCM")
	} else if strings.Contains(upper, "AES_256_CBC") {
		algs = append(algs, "AES-256-CBC")
	} else if strings.Contains(upper, "AES_128_CBC") {
		algs = append(algs, "AES-128-CBC")
	} else if strings.Contains(upper, "CHACHA20") {
		algs = append(algs, "ChaCha20-Poly1305")
	}

	// Hash/MAC
	if strings.Contains(upper, "SHA384") {
		algs = append(algs, "SHA-384")
	} else if strings.Contains(upper, "SHA256") {
		algs = append(algs, "SHA-256")
	} else if strings.Contains(upper, "SHA512") {
		algs = append(algs, "SHA-512")
	}

	// Authentication
	if strings.Contains(upper, "ECDSA") {
		algs = append(algs, "ECDSA")
	} else if strings.Contains(upper, "RSA") && !strings.Contains(upper, "ECDHE") {
		algs = append(algs, "RSA")
	}

	if len(algs) == 0 {
		algs = append(algs, suite)
	}

	return algs
}

func getClassicalSecurity(suite string) int {
	upper := strings.ToUpper(suite)
	switch {
	case strings.Contains(upper, "AES_256"):
		return 256
	case strings.Contains(upper, "AES_128"):
		return 128
	case strings.Contains(upper, "CHACHA20"):
		return 256
	case strings.Contains(upper, "AES_192"):
		return 192
	default:
		return 128
	}
}

func getQuantumSecurity(suite string) int {
	upper := strings.ToUpper(suite)

	// If PQC key exchange, quantum security is maintained
	if strings.Contains(upper, "KYBER") || strings.Contains(upper, "MLKEM") {
		return 128
	}

	// Grover's halves symmetric security
	switch {
	case strings.Contains(upper, "AES_256"):
		return 128 // 256/2
	case strings.Contains(upper, "AES_128"):
		return 64 // 128/2 — broken
	case strings.Contains(upper, "CHACHA20"):
		return 128 // 256/2
	default:
		return 0 // Key exchange broken by Shor's
	}
}

func getKeyClassicalSecurity(alg string, keySize int) int {
	upper := strings.ToUpper(alg)
	switch {
	case strings.Contains(upper, "RSA"):
		switch {
		case keySize >= 4096:
			return 152
		case keySize >= 3072:
			return 128
		case keySize >= 2048:
			return 112
		case keySize >= 1024:
			return 80
		default:
			return 64
		}
	case strings.Contains(upper, "ECDSA") || strings.Contains(upper, "EC"):
		switch {
		case keySize >= 521:
			return 256
		case keySize >= 384:
			return 192
		case keySize >= 256:
			return 128
		default:
			return 80
		}
	case strings.Contains(upper, "ED25519"):
		return 128
	case strings.Contains(upper, "ML-DSA") || strings.Contains(upper, "DILITHIUM"):
		return 128
	default:
		return 0
	}
}
