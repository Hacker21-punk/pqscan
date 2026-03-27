package main

import "strings"

func extractKeyExchange(cipherSuite string) string {
	suite := strings.ToUpper(cipherSuite)

	switch {
	case strings.Contains(suite, "ECDHE"):
		return "ECDHE (Elliptic Curve Diffie-Hellman)"
	case strings.Contains(suite, "DHE"):
		return "DHE (Diffie-Hellman Ephemeral)"
	case strings.Contains(suite, "RSA"):
		return "RSA Key Transport"
	case strings.Contains(suite, "CECPQ"):
		return "CECPQ2 (Hybrid Post-Quantum)"
	case strings.Contains(suite, "KYBER"),
		strings.Contains(suite, "MLKEM"):
		return "ML-KEM (Post-Quantum Safe)"
	default:
		// TLS 1.3 cipher suites don't include key exchange
		// in the name — key exchange is negotiated separately
		return "ECDHE (TLS 1.3 default)"
	}
}

func classifyRisk(cipherSuite string) string {
	suite := strings.ToUpper(cipherSuite)

	// Check for post-quantum safe
	if strings.Contains(suite, "KYBER") ||
		strings.Contains(suite, "MLKEM") ||
		strings.Contains(suite, "CECPQ") {
		return "SAFE"
	}

	// Check for classically broken (should not exist but might)
	if strings.Contains(suite, "RC4") ||
		strings.Contains(suite, "DES_CBC") ||
		strings.Contains(suite, "NULL") ||
		strings.Contains(suite, "EXPORT") ||
		strings.Contains(suite, "MD5") {
		return "CRITICAL (classically broken AND quantum broken)"
	}

	// All RSA, DHE, ECDHE key exchanges are broken by Shor's
	if strings.Contains(suite, "RSA") ||
		strings.Contains(suite, "ECDHE") ||
		strings.Contains(suite, "DHE") {
		return "CRITICAL"
	}

	// TLS 1.3 suites (AES-128-GCM, AES-256-GCM, CHACHA20)
	// Key exchange in TLS 1.3 is always ECDHE or DHE → broken
	if strings.Contains(suite, "TLS_AES") ||
		strings.Contains(suite, "TLS_CHACHA") {
		return "CRITICAL"
	}

	return "CRITICAL"
}

func classifyQuantumThreat(cipherSuite string) string {
	suite := strings.ToUpper(cipherSuite)

	if strings.Contains(suite, "KYBER") ||
		strings.Contains(suite, "MLKEM") {
		return "None — Post-Quantum Safe"
	}

	if strings.Contains(suite, "RSA") ||
		strings.Contains(suite, "ECDHE") ||
		strings.Contains(suite, "DHE") {
		return "Shor's Algorithm — Key exchange COMPLETELY BROKEN"
	}

	// TLS 1.3 uses ECDHE/DHE key exchange even though
	// suite name only shows symmetric cipher
	if strings.Contains(suite, "TLS_AES") ||
		strings.Contains(suite, "TLS_CHACHA") {
		return "Shor's Algorithm — Key exchange (ECDHE) COMPLETELY BROKEN"
	}

	return "Shor's Algorithm — Likely BROKEN"
}

func getRemediation(cipherSuite string) string {
	suite := strings.ToUpper(cipherSuite)

	if strings.Contains(suite, "KYBER") ||
		strings.Contains(suite, "MLKEM") {
		return "No action needed — already quantum safe"
	}

	if strings.Contains(suite, "RSA") {
		return "Replace RSA key exchange with ML-KEM-768 (hybrid X25519+ML-KEM-768 recommended)"
	}

	if strings.Contains(suite, "ECDHE") ||
		strings.Contains(suite, "TLS_AES") ||
		strings.Contains(suite, "TLS_CHACHA") {
		return "Upgrade to hybrid PQC key exchange: X25519+ML-KEM-768"
	}

	return "Migrate to CNSA 2.0 approved algorithms"
}

func classifyCertRisk(keyAlgorithm string) string {
	alg := strings.ToUpper(keyAlgorithm)

	switch {
	case strings.Contains(alg, "RSA"):
		return "CRITICAL — RSA broken by Shor's algorithm"
	case strings.Contains(alg, "ECDSA"),
		strings.Contains(alg, "EC"):
		return "CRITICAL — ECDSA broken by Shor's algorithm"
	case strings.Contains(alg, "ED25519"):
		return "CRITICAL — Ed25519 broken by Shor's algorithm"
	case strings.Contains(alg, "DILITHIUM"),
		strings.Contains(alg, "ML-DSA"):
		return "SAFE — Post-quantum signature algorithm"
	case strings.Contains(alg, "SPHINCS"),
		strings.Contains(alg, "SLH-DSA"):
		return "SAFE — Post-quantum signature algorithm"
	default:
		return "UNKNOWN — Manual review needed"
	}
}