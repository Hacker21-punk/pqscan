package main

import "strings"

// Risk level constants used throughout the scanner.
// Three distinct tiers, aligned with CNSA 2.0 interim guidance:
//
//	SAFE         — post-quantum hybrid key exchange negotiated;
//	               no action required.
//
//	HNDL-EXPOSED — modern classical crypto (ECDHE, RSA-kex, TLS 1.3 default).
//	               Not classically broken TODAY, but traffic is exposed to
//	               "Harvest Now, Decrypt Later" attacks and will be fully broken
//	               by a cryptographically-relevant quantum computer (Shor's algorithm).
//
//	CRITICAL     — classically broken NOW (RC4, NULL, EXPORT, MD5, 3DES, ANON).
//	               Requires immediate remediation regardless of quantum timeline.
const (
	RiskSafe     = "SAFE"
	RiskHNDL     = "HNDL-EXPOSED"
	RiskCritical = "CRITICAL"
)

// isVulnerable reports whether risk is not quantum-safe.
// Use this instead of bare strings.Contains(risk, "CRITICAL") in logic that
// must treat HNDL-EXPOSED as a vulnerability for scoring and exit-code purposes.
func isVulnerable(risk string) bool { return risk != RiskSafe }

// isCritical reports whether risk is the CRITICAL tier (classically broken now).
func isCritical(risk string) bool { return risk == RiskCritical }

// extractKeyExchange infers the key-exchange mechanism from a cipher suite name.
// For TLS 1.3 connections callers MUST inspect state.CurveID via
// classifyTLSConnection before calling this, because TLS 1.3 suite names
// (e.g. TLS_AES_256_GCM_SHA384) never encode the key-exchange group.
func extractKeyExchange(cipherSuite string) string {
	suite := strings.ToUpper(cipherSuite)
	switch {
	case strings.Contains(suite, "CECPQ"):
		return "CECPQ2 (Hybrid Post-Quantum)"
	case strings.Contains(suite, "KYBER"), strings.Contains(suite, "MLKEM"):
		return "ML-KEM (Post-Quantum Safe)"
	case strings.Contains(suite, "ECDHE"):
		return "ECDHE (Elliptic Curve Diffie-Hellman)"
	case strings.Contains(suite, "DHE"):
		return "DHE (Diffie-Hellman Ephemeral)"
	case strings.Contains(suite, "RSA"):
		return "RSA Key Transport"
	default:
		// TLS 1.3: key exchange is negotiated independently of the suite name.
		// The actual group is in state.CurveID — see classifyTLSConnection.
		return "ECDHE (TLS 1.3, group from CurveID)"
	}
}

// classifyRisk returns a risk tier based on the cipher suite name alone.
// For TLS 1.3 connections use classifyTLSConnection instead, which first
// inspects state.CurveID and falls back to this function.
func classifyRisk(cipherSuite string) string {
	suite := strings.ToUpper(cipherSuite)

	// Post-quantum safe via suite name (fallback path for non-TLS 1.3).
	if strings.Contains(suite, "KYBER") ||
		strings.Contains(suite, "MLKEM") ||
		strings.Contains(suite, "CECPQ") {
		return RiskSafe
	}

	// Classically broken TODAY — highest severity, independent of quantum threat.
	if strings.Contains(suite, "RC4") ||
		strings.Contains(suite, "DES_CBC") ||
		strings.Contains(suite, "3DES") ||
		strings.Contains(suite, "_NULL_") ||
		strings.Contains(suite, "NULL_SHA") ||
		strings.Contains(suite, "EXPORT") ||
		strings.Contains(suite, "_MD5") ||
		strings.Contains(suite, "ANON") {
		return RiskCritical
	}

	// Modern classical crypto — not broken today but quantum-vulnerable.
	// Covers ECDHE (TLS 1.2), RSA key transport, and all TLS 1.3 suites
	// (TLS_AES_*, TLS_CHACHA20_*) whose key-exchange group is ECDHE by default.
	return RiskHNDL
}

func classifyQuantumThreat(cipherSuite string) string {
	suite := strings.ToUpper(cipherSuite)

	if strings.Contains(suite, "KYBER") || strings.Contains(suite, "MLKEM") {
		return "None — post-quantum safe key exchange"
	}
	if strings.Contains(suite, "RC4") ||
		strings.Contains(suite, "_NULL_") ||
		strings.Contains(suite, "NULL_SHA") ||
		strings.Contains(suite, "EXPORT") ||
		strings.Contains(suite, "_MD5") {
		return "Classically broken NOW; also vulnerable to Shor's algorithm"
	}
	if strings.Contains(suite, "RSA") ||
		strings.Contains(suite, "ECDHE") ||
		strings.Contains(suite, "DHE") {
		return "Shor's algorithm breaks the key exchange (Harvest Now, Decrypt Later)"
	}
	// TLS 1.3 default path — ECDHE group negotiated separately
	return "Shor's algorithm breaks ECDHE key exchange (Harvest Now, Decrypt Later)"
}

func getRemediation(cipherSuite string) string {
	suite := strings.ToUpper(cipherSuite)

	if strings.Contains(suite, "KYBER") || strings.Contains(suite, "MLKEM") {
		return "No action needed — already quantum safe"
	}
	if strings.Contains(suite, "RC4") ||
		strings.Contains(suite, "_NULL_") ||
		strings.Contains(suite, "NULL_SHA") ||
		strings.Contains(suite, "EXPORT") ||
		strings.Contains(suite, "_MD5") {
		return "Disable immediately — cipher is classically broken today"
	}
	if strings.Contains(suite, "RSA") {
		return "Replace RSA key exchange with X25519+ML-KEM-768 hybrid (FIPS 203)"
	}
	// ECDHE (TLS 1.2) or TLS 1.3 default
	return "Enable X25519+ML-KEM-768 hybrid key exchange (FIPS 203, Go 1.24+ default)"
}

func classifyCertRisk(keyAlgorithm string) string {
	alg := strings.ToUpper(keyAlgorithm)

	switch {
	case strings.Contains(alg, "RSA"):
		return "CRITICAL — RSA broken by Shor's algorithm"
	case strings.Contains(alg, "ECDSA"), strings.Contains(alg, "EC"):
		return "CRITICAL — ECDSA broken by Shor's algorithm"
	case strings.Contains(alg, "ED25519"):
		return "CRITICAL — Ed25519 broken by Shor's algorithm"
	case strings.Contains(alg, "DILITHIUM"), strings.Contains(alg, "ML-DSA"):
		return "SAFE — Post-quantum signature algorithm"
	case strings.Contains(alg, "SPHINCS"), strings.Contains(alg, "SLH-DSA"):
		return "SAFE — Post-quantum signature algorithm"
	default:
		return "UNKNOWN — Manual review needed"
	}
}