package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fatih/color"
)

// CipherEnumResult holds complete cipher enumeration results
type CipherEnumResult struct {
	Host              string
	Port              int
	SupportedVersions []TLSVersionResult
	SupportedCiphers  []CipherResult
	SupportedCurves   []CurveResult
	PrefersCipherOrder bool
	HasPQCSupport     bool
	PQCDetails        string
	TotalCiphers      int
	WeakCiphers       int
	QuantumVulnerable int
	QuantumSafe       int
}

type TLSVersionResult struct {
	Name      string
	Version   uint16
	Supported bool
	Risk      string
}

type CipherResult struct {
	Name           string
	ID             uint16
	Supported      bool
	TLSVersion     string
	KeyExchange    string
	Authentication string
	Encryption     string
	Hash           string
	RiskLevel      string
	QuantumRisk    string
	Classical      int // classical security bits
	Quantum        int // post-quantum security bits
}

type CurveResult struct {
	Name        string
	ID          tls.CurveID
	Supported   bool
	QuantumRisk string
	IsPQC       bool
}

// TLS versions to test
var tlsVersions = []struct {
	Name    string
	Version uint16
	Risk    string
}{
	{"SSL 3.0", 0x0300, "CRITICAL — Broken classically (POODLE)"},
	{"TLS 1.0", tls.VersionTLS10, "HIGH — Deprecated, weak ciphers"},
	{"TLS 1.1", tls.VersionTLS11, "HIGH — Deprecated"},
	{"TLS 1.2", tls.VersionTLS12, "MODERATE — Quantum-vulnerable key exchange"},
	{"TLS 1.3", tls.VersionTLS13, "MODERATE — Quantum-vulnerable key exchange (ECDHE)"},
}

// TLS 1.2 cipher suites to test
var tls12CipherSuites = []struct {
	Name           string
	ID             uint16
	KeyExchange    string
	Authentication string
	Encryption     string
	Hash           string
	RiskLevel      string
}{
	// ECDHE + ECDSA (modern, but quantum-vulnerable)
	{"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384, "ECDHE", "ECDSA", "AES-256-GCM", "SHA-384", "CRITICAL"},
	{"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, "ECDHE", "ECDSA", "AES-128-GCM", "SHA-256", "CRITICAL"},
	{"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE", "ECDSA", "ChaCha20-Poly1305", "SHA-256", "CRITICAL"},

	// ECDHE + RSA (common, quantum-vulnerable)
	{"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, "ECDHE", "RSA", "AES-256-GCM", "SHA-384", "CRITICAL"},
	{"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, "ECDHE", "RSA", "AES-128-GCM", "SHA-256", "CRITICAL"},
	{"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256, "ECDHE", "RSA", "ChaCha20-Poly1305", "SHA-256", "CRITICAL"},
	{"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA, "ECDHE", "RSA", "AES-256-CBC", "SHA-1", "CRITICAL"},
	{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA, "ECDHE", "RSA", "AES-128-CBC", "SHA-1", "CRITICAL"},
	{"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256, "ECDHE", "RSA", "AES-128-CBC", "SHA-256", "CRITICAL"},

	// RSA key transport (worst — no forward secrecy + quantum-vulnerable)
	{"TLS_RSA_WITH_AES_256_GCM_SHA384", tls.TLS_RSA_WITH_AES_256_GCM_SHA384, "RSA", "RSA", "AES-256-GCM", "SHA-384", "CRITICAL"},
	{"TLS_RSA_WITH_AES_128_GCM_SHA256", tls.TLS_RSA_WITH_AES_128_GCM_SHA256, "RSA", "RSA", "AES-128-GCM", "SHA-256", "CRITICAL"},
	{"TLS_RSA_WITH_AES_256_CBC_SHA", tls.TLS_RSA_WITH_AES_256_CBC_SHA, "RSA", "RSA", "AES-256-CBC", "SHA-1", "CRITICAL"},
	{"TLS_RSA_WITH_AES_128_CBC_SHA", tls.TLS_RSA_WITH_AES_128_CBC_SHA, "RSA", "RSA", "AES-128-CBC", "SHA-1", "CRITICAL"},
	{"TLS_RSA_WITH_AES_128_CBC_SHA256", tls.TLS_RSA_WITH_AES_128_CBC_SHA256, "RSA", "RSA", "AES-128-CBC", "SHA-256", "CRITICAL"},

	// 3DES (classically broken)
	{"TLS_RSA_WITH_3DES_EDE_CBC_SHA", tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA, "RSA", "RSA", "3DES-CBC", "SHA-1", "CRITICAL"},
	{"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA", tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA, "ECDHE", "RSA", "3DES-CBC", "SHA-1", "CRITICAL"},
}

// TLS 1.3 cipher suites
var tls13CipherSuites = []struct {
	Name       string
	ID         uint16
	Encryption string
	Hash       string
}{
	{"TLS_AES_128_GCM_SHA256", tls.TLS_AES_128_GCM_SHA256, "AES-128-GCM", "SHA-256"},
	{"TLS_AES_256_GCM_SHA384", tls.TLS_AES_256_GCM_SHA384, "AES-256-GCM", "SHA-384"},
	{"TLS_CHACHA20_POLY1305_SHA256", tls.TLS_CHACHA20_POLY1305_SHA256, "ChaCha20-Poly1305", "SHA-256"},
}

// Curves/Groups to test
var curvesToTest = []struct {
	Name string
	ID   tls.CurveID
	IsPQC bool
}{
	{"X25519", tls.X25519, false},
	{"P-256", tls.CurveP256, false},
	{"P-384", tls.CurveP384, false},
	{"P-521", tls.CurveP521, false},
	// PQC hybrid curve IDs (IETF assignments)
	{"X25519Kyber768Draft00", tls.CurveID(0x6399), true},
	{"X25519MLKEM768", tls.CurveID(0x11EC), true},
	{"SecP256r1MLKEM768", tls.CurveID(0x11EB), true},
}

// EnumerateCiphers performs full cipher suite enumeration
func EnumerateCiphers(host string, port int) (*CipherEnumResult, error) {
	result := &CipherEnumResult{
		Host: host,
		Port: port,
	}

	// 1. Test TLS versions
	result.SupportedVersions = testTLSVersions(host, port)

	// 2. Test TLS 1.2 cipher suites
	tls12Supported := testTLS12Ciphers(host, port)
	result.SupportedCiphers = append(result.SupportedCiphers, tls12Supported...)

	// 3. Test TLS 1.3 cipher suites
	tls13Supported := testTLS13Ciphers(host, port)
	result.SupportedCiphers = append(result.SupportedCiphers, tls13Supported...)

	// 4. Test curves/groups (including PQC)
	result.SupportedCurves = testCurves(host, port)

	// 5. Check cipher order preference
	result.PrefersCipherOrder = testCipherOrder(host, port)

	// 6. Count stats
	for _, c := range result.SupportedCiphers {
		if c.Supported {
			result.TotalCiphers++
			if strings.Contains(c.RiskLevel, "CRITICAL") {
				result.QuantumVulnerable++
			}
			if c.QuantumRisk == "SAFE" {
				result.QuantumSafe++
			}
			if isWeakCipher(c.Name) {
				result.WeakCiphers++
			}
		}
	}

	// 7. Check PQC support from curves
	for _, curve := range result.SupportedCurves {
		if curve.Supported && curve.IsPQC {
			result.HasPQCSupport = true
			result.PQCDetails = fmt.Sprintf("Server supports %s (hybrid post-quantum key exchange)", curve.Name)
			break
		}
	}

	return result, nil
}

func testTLSVersions(host string, port int) []TLSVersionResult {
	var results []TLSVersionResult
	address := fmt.Sprintf("%s:%d", host, port)

	for _, v := range tlsVersions {
		supported := false

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp", address,
			&tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         v.Version,
				MaxVersion:         v.Version,
				ServerName:         host,
			},
		)

		if err == nil {
			supported = true
			conn.Close()
		}

		results = append(results, TLSVersionResult{
			Name:      v.Name,
			Version:   v.Version,
			Supported: supported,
			Risk:      v.Risk,
		})
	}

	return results
}

func testTLS12Ciphers(host string, port int) []CipherResult {
	var results []CipherResult
	address := fmt.Sprintf("%s:%d", host, port)

	for _, cs := range tls12CipherSuites {
		supported := false
		negotiatedVersion := ""

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp", address,
			&tls.Config{
				InsecureSkipVerify: true,
				CipherSuites:      []uint16{cs.ID},
				MinVersion:         tls.VersionTLS10,
				MaxVersion:         tls.VersionTLS12,
				ServerName:         host,
			},
		)

		if err == nil {
			supported = true
			state := conn.ConnectionState()
			negotiatedVersion = tlsVersionName(state.Version)
			conn.Close()
		}

		quantumRisk := "BROKEN — Shor's algorithm"
		quantumBits := 0
		classicalBits := getClassicalBitsForCipher(cs.Encryption)

		result := CipherResult{
			Name:           cs.Name,
			ID:             cs.ID,
			Supported:      supported,
			TLSVersion:     negotiatedVersion,
			KeyExchange:    cs.KeyExchange,
			Authentication: cs.Authentication,
			Encryption:     cs.Encryption,
			Hash:           cs.Hash,
			RiskLevel:      cs.RiskLevel,
			QuantumRisk:    quantumRisk,
			Classical:      classicalBits,
			Quantum:        quantumBits,
		}

		results = append(results, result)
	}

	return results
}

func testTLS13Ciphers(host string, port int) []CipherResult {
	var results []CipherResult
	address := fmt.Sprintf("%s:%d", host, port)

	for _, cs := range tls13CipherSuites {
		supported := false

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp", address,
			&tls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tls.VersionTLS13,
				MaxVersion:         tls.VersionTLS13,
				ServerName:         host,
			},
		)

		if err == nil {
			state := conn.ConnectionState()
			if tls.CipherSuiteName(state.CipherSuite) == cs.Name {
				supported = true
			}
			conn.Close()
		}

		// TLS 1.3 key exchange is always ECDHE (or PQC hybrid)
		quantumRisk := "BROKEN — Key exchange (ECDHE) broken by Shor's"
		quantumBits := 0
		classicalBits := getClassicalBitsForCipher(cs.Encryption)

		result := CipherResult{
			Name:           cs.Name,
			Supported:      supported,
			TLSVersion:     "TLS 1.3",
			KeyExchange:    "ECDHE (TLS 1.3)",
			Authentication: "Certificate",
			Encryption:     cs.Encryption,
			Hash:           cs.Hash,
			RiskLevel:      "CRITICAL",
			QuantumRisk:    quantumRisk,
			Classical:      classicalBits,
			Quantum:        quantumBits,
		}

		results = append(results, result)
	}

	return results
}

func testCurves(host string, port int) []CurveResult {
	var results []CurveResult
	address := fmt.Sprintf("%s:%d", host, port)

	for _, curve := range curvesToTest {
		supported := false

		conn, err := tls.DialWithDialer(
			&net.Dialer{Timeout: 3 * time.Second},
			"tcp", address,
			&tls.Config{
				InsecureSkipVerify: true,
				CurvePreferences:  []tls.CurveID{curve.ID},
				MinVersion:        tls.VersionTLS12,
				ServerName:        host,
			},
		)

		if err == nil {
			supported = true
			conn.Close()
		}

		quantumRisk := "BROKEN — Shor's algorithm"
		if curve.IsPQC {
			quantumRisk = "SAFE — Post-quantum hybrid"
		}

		results = append(results, CurveResult{
			Name:        curve.Name,
			ID:          curve.ID,
			Supported:   supported,
			QuantumRisk: quantumRisk,
			IsPQC:       curve.IsPQC,
		})
	}

	return results
}

func testCipherOrder(host string, port int) bool {
	address := fmt.Sprintf("%s:%d", host, port)

	// Connect with weaker cipher first in our preference
	conn1, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", address,
		&tls.Config{
			InsecureSkipVerify: true,
			CipherSuites: []uint16{
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			},
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			ServerName: host,
		},
	)

	if err != nil {
		return false
	}
	cipher1 := conn1.ConnectionState().CipherSuite
	conn1.Close()

	// Connect with stronger cipher first
	conn2, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second},
		"tcp", address,
		&tls.Config{
			InsecureSkipVerify: true,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			},
			MinVersion: tls.VersionTLS12,
			MaxVersion: tls.VersionTLS12,
			ServerName: host,
		},
	)

	if err != nil {
		return false
	}
	cipher2 := conn2.ConnectionState().CipherSuite
	conn2.Close()

	// If server always picks the same cipher regardless of our order,
	// it enforces its own preference (good)
	return cipher1 == cipher2
}

func getClassicalBitsForCipher(encryption string) int {
	upper := strings.ToUpper(encryption)
	switch {
	case strings.Contains(upper, "256"):
		return 256
	case strings.Contains(upper, "128"):
		return 128
	case strings.Contains(upper, "192"):
		return 192
	case strings.Contains(upper, "CHACHA20"):
		return 256
	case strings.Contains(upper, "3DES"):
		return 112
	default:
		return 128
	}
}

func isWeakCipher(name string) bool {
	upper := strings.ToUpper(name)
	weakPatterns := []string{
		"3DES", "RC4", "DES_CBC", "NULL", "EXPORT",
		"MD5", "CBC_SHA", // CBC with SHA-1 is considered weak
	}
	for _, pattern := range weakPatterns {
		if strings.Contains(upper, pattern) {
			return true
		}
	}
	return false
}

// PrintCipherEnumReport prints the cipher enumeration results
func PrintCipherEnumReport(result *CipherEnumResult) {
	red := color.New(color.FgRed, color.Bold)
	green := color.New(color.FgGreen, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	white := color.New(color.FgWhite, color.Bold)
	cyan := color.New(color.FgCyan)
	dim := color.New(color.FgWhite)

	fmt.Println()
	white.Printf(" 🔐 CIPHER ENUMERATION — %s:%d\n", result.Host, result.Port)
	fmt.Println(" " + strings.Repeat("─", 60))

	// TLS Versions
	fmt.Println()
	white.Println("   TLS VERSION SUPPORT:")
	for _, v := range result.SupportedVersions {
		if v.Supported {
			if strings.Contains(v.Name, "1.0") || strings.Contains(v.Name, "1.1") || strings.Contains(v.Name, "SSL") {
				red.Printf("     ⚠ %-10s  ENABLED   %s\n", v.Name, v.Risk)
			} else {
				cyan.Printf("     ✓ %-10s  ENABLED   %s\n", v.Name, v.Risk)
			}
		} else {
			dim.Printf("     ✗ %-10s  disabled\n", v.Name)
		}
	}

	// Supported Curves
	fmt.Println()
	white.Println("   KEY EXCHANGE GROUPS / CURVES:")
	pqcFound := false
	for _, c := range result.SupportedCurves {
		if c.Supported {
			if c.IsPQC {
				green.Printf("     🟢 %-25s  SUPPORTED  %s\n", c.Name, c.QuantumRisk)
				pqcFound = true
			} else {
				red.Printf("     🔴 %-25s  SUPPORTED  %s\n", c.Name, c.QuantumRisk)
			}
		} else {
			if c.IsPQC {
				yellow.Printf("     ○  %-25s  not supported (PQC not available)\n", c.Name)
			} else {
				dim.Printf("     ○  %-25s  not supported\n", c.Name)
			}
		}
	}

	// PQC Status
	fmt.Println()
	if pqcFound {
		green.Println("   🔬 PQC KEY EXCHANGE: DETECTED ✅")
		green.Printf("      %s\n", result.PQCDetails)
		green.Println("      This server supports post-quantum hybrid key exchange!")
	} else {
		red.Println("   🔬 PQC KEY EXCHANGE: NOT AVAILABLE ❌")
		yellow.Println("      Server does not support any post-quantum key exchange.")
		yellow.Println("      All key exchanges are vulnerable to Shor's algorithm.")
	}

	// Cipher suites
	fmt.Println()
	white.Println("   SUPPORTED CIPHER SUITES:")
	fmt.Println()

	supportedCount := 0
	for _, c := range result.SupportedCiphers {
		if !c.Supported {
			continue
		}
		supportedCount++

		riskIcon := "🔴"
		riskColor := red
		if c.QuantumRisk == "SAFE" {
			riskIcon = "🟢"
			riskColor = green
		}

		weak := ""
		if isWeakCipher(c.Name) {
			weak = " ⚠ WEAK"
		}

		riskColor.Printf("     %s %s%s\n", riskIcon, c.Name, weak)
		dim.Printf("        KEX: %-10s  Auth: %-8s  Enc: %-18s  Hash: %s\n",
			c.KeyExchange, c.Authentication, c.Encryption, c.Hash)
		dim.Printf("        Classical: %d-bit   Quantum: %d-bit   %s\n",
			c.Classical, c.Quantum, c.QuantumRisk)
		fmt.Println()
	}

	// Not supported (only show if verbose)
	notSupported := 0
	for _, c := range result.SupportedCiphers {
		if !c.Supported {
			notSupported++
		}
	}
	dim.Printf("   (%d cipher suites tested, %d supported, %d rejected)\n",
		len(result.SupportedCiphers), supportedCount, notSupported)

	// Cipher order preference
	fmt.Println()
	if result.PrefersCipherOrder {
		green.Println("   ✓ Server enforces cipher order preference (good)")
	} else {
		yellow.Println("   ⚠ Server follows client cipher preference")
		yellow.Println("     An attacker could force a weaker cipher suite")
	}

	// Summary
	fmt.Println()
	fmt.Println(" " + strings.Repeat("─", 60))
	white.Println("   SUMMARY:")
	cyan.Printf("     Total supported ciphers:     %d\n", result.TotalCiphers)
	red.Printf("     Quantum-vulnerable ciphers:  %d\n", result.QuantumVulnerable)
	green.Printf("     Quantum-safe ciphers:        %d\n", result.QuantumSafe)
	if result.WeakCiphers > 0 {
		red.Printf("     Classically weak ciphers:    %d ⚠\n", result.WeakCiphers)
	}

	if result.HasPQCSupport {
		fmt.Println()
		green.Println("   ✅ This server has post-quantum support!")
		green.Println("      Traffic using PQC key exchange is quantum-safe.")
	} else {
		fmt.Println()
		red.Println("   ❌ No post-quantum support detected.")
		red.Println("      ALL traffic is vulnerable to future quantum decryption.")
		fmt.Println()
		yellow.Println("   Recommended actions:")
		yellow.Println("     1. Enable X25519Kyber768 hybrid key exchange")
		yellow.Println("     2. Update TLS library to support ML-KEM")
		yellow.Println("     3. Configure server to prefer PQC cipher suites")
	}

	fmt.Println()
}
