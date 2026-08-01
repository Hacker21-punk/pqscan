package main

import "testing"

// --------------------------------------------------------------------------
// classifyRisk
// --------------------------------------------------------------------------

func TestClassifyRisk(t *testing.T) {
	tests := []struct {
		name      string
		suite     string
		wantRisk  string
	}{
		// PQC — must be SAFE
		{"MLKEM suite", "TLS_AES_256_GCM_SHA384_MLKEM768", RiskSafe},
		{"KYBER suite", "TLS_ECDHE_RSA_WITH_KYBER_768_AES_256_GCM_SHA384", RiskSafe},
		{"CECPQ2 suite", "TLS_CECPQ2_RSA_WITH_AES_256_GCM_SHA384", RiskSafe},

		// Classically broken — must be CRITICAL
		{"RC4", "TLS_RSA_WITH_RC4_128_SHA", RiskCritical},
		{"NULL cipher", "TLS_RSA_WITH_NULL_SHA", RiskCritical},
		{"EXPORT cipher", "TLS_RSA_EXPORT_WITH_RC4_40_MD5", RiskCritical},
		{"MD5 suite", "TLS_RSA_WITH_RC4_128_MD5", RiskCritical},
		{"3DES", "TLS_RSA_WITH_3DES_EDE_CBC_SHA", RiskCritical},
		{"ANON", "TLS_DH_ANON_WITH_AES_128_CBC_SHA", RiskCritical},

		// Modern classical — must be HNDL-EXPOSED
		{"TLS 1.3 AES-256-GCM", "TLS_AES_256_GCM_SHA384", RiskHNDL},
		{"TLS 1.3 ChaCha20", "TLS_CHACHA20_POLY1305_SHA256", RiskHNDL},
		{"ECDHE-RSA-AES256-GCM", "ECDHE_RSA_WITH_AES_256_GCM_SHA384", RiskHNDL},
		{"ECDHE-ECDSA-AES128-GCM", "ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", RiskHNDL},
		{"DHE-RSA-AES256", "DHE_RSA_WITH_AES_256_CBC_SHA256", RiskHNDL},
		{"RSA-AES256-GCM", "RSA_WITH_AES_256_GCM_SHA384", RiskHNDL},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyRisk(tc.suite)
			if got != tc.wantRisk {
				t.Errorf("classifyRisk(%q) = %q, want %q", tc.suite, got, tc.wantRisk)
			}
		})
	}
}

// --------------------------------------------------------------------------
// extractKeyExchange
// --------------------------------------------------------------------------

func TestExtractKeyExchange(t *testing.T) {
	tests := []struct {
		suite string
		want  string
	}{
		{"ECDHE_RSA_WITH_AES_256_GCM_SHA384", "ECDHE (Elliptic Curve Diffie-Hellman)"},
		{"DHE_RSA_WITH_AES_256_CBC_SHA", "DHE (Diffie-Hellman Ephemeral)"},
		{"RSA_WITH_AES_256_GCM_SHA384", "RSA Key Transport"},
		{"CECPQ2_RSA_WITH_AES_256_GCM_SHA384", "CECPQ2 (Hybrid Post-Quantum)"},
		{"TLS_AES_256_GCM_SHA384", "ECDHE (TLS 1.3, group from CurveID)"},
	}

	for _, tc := range tests {
		t.Run(tc.suite, func(t *testing.T) {
			got := extractKeyExchange(tc.suite)
			if got != tc.want {
				t.Errorf("extractKeyExchange(%q) = %q, want %q", tc.suite, got, tc.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// classifyCertRisk
// --------------------------------------------------------------------------

func TestClassifyCertRisk(t *testing.T) {
	tests := []struct {
		alg  string
		want string
	}{
		{"RSA", "CRITICAL — RSA broken by Shor's algorithm"},
		{"ECDSA P-256", "CRITICAL — ECDSA broken by Shor's algorithm"},
		{"Ed25519", "CRITICAL — Ed25519 broken by Shor's algorithm"},
		{"ML-DSA-65", "SAFE — Post-quantum signature algorithm"},
		{"SLH-DSA-SHA2-128s", "SAFE — Post-quantum signature algorithm"},
		{"DILITHIUM3", "SAFE — Post-quantum signature algorithm"},
		{"", "UNKNOWN — Manual review needed"},
	}

	for _, tc := range tests {
		t.Run(tc.alg, func(t *testing.T) {
			got := classifyCertRisk(tc.alg)
			if got != tc.want {
				t.Errorf("classifyCertRisk(%q) = %q, want %q", tc.alg, got, tc.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// classifySSHHostKey
// --------------------------------------------------------------------------

func TestClassifySSHHostKey(t *testing.T) {
	tests := []struct {
		keyType string
		want    string
	}{
		{"ssh-rsa", "CRITICAL — RSA broken by Shor's algorithm"},
		{"ecdsa-sha2-nistp256", "CRITICAL — ECDSA broken by Shor's algorithm"},
		{"ssh-ed25519", "CRITICAL — Ed25519 broken by Shor's algorithm"},
		{"ssh-dss", "CRITICAL — DSA broken classically AND by Shor's"},
		{"sntrup761x25519-sha512@openssh.com", "SAFE — Post-quantum hybrid key"},
		{"mlkem768x25519-sha256", "SAFE — Post-quantum key encapsulation"},
	}

	for _, tc := range tests {
		t.Run(tc.keyType, func(t *testing.T) {
			got := classifySSHHostKey(tc.keyType)
			if got != tc.want {
				t.Errorf("classifySSHHostKey(%q) = %q, want %q", tc.keyType, got, tc.want)
			}
		})
	}
}

// --------------------------------------------------------------------------
// isVulnerable / isCritical helpers
// --------------------------------------------------------------------------

func TestRiskHelpers(t *testing.T) {
	if isVulnerable(RiskSafe) {
		t.Error("isVulnerable(SAFE) should be false")
	}
	if !isVulnerable(RiskHNDL) {
		t.Error("isVulnerable(HNDL-EXPOSED) should be true")
	}
	if !isVulnerable(RiskCritical) {
		t.Error("isVulnerable(CRITICAL) should be true")
	}
	if isCritical(RiskHNDL) {
		t.Error("isCritical(HNDL-EXPOSED) should be false")
	}
	if !isCritical(RiskCritical) {
		t.Error("isCritical(CRITICAL) should be true")
	}
}
