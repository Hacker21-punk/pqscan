package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
)

type ScanResult struct {
	Host          string
	Port          int
	Protocol      string
	Service       string
	CipherSuite   string
	KeyExchange   string
	Certificate   CertInfo
	RiskLevel     string
	QuantumThreat string
	Remediation   string
	Error         string
}

type CertInfo struct {
	Subject      string
	Issuer       string
	KeyAlgorithm string
	KeySize      int
	SignatureAlg string
	NotAfter     time.Time
	SANs         []string
}

type SSHAlgorithms struct {
	KeyExchanges []string
	HostKeys     []string
	Ciphers      []string
	MACs         []string
}

// Port definitions with service types
type PortDef struct {
	Port    int
	Service string
	Type    string // "tls", "ssh", "starttls-smtp", "starttls-imap", "starttls-pop3"
}

func getDefaultPorts() []PortDef {
	return []PortDef{
		// TLS ports
		{443, "HTTPS", "tls"},
		{8443, "HTTPS-Alt", "tls"},
		{4443, "HTTPS-Alt", "tls"},

		// SSH
		{22, "SSH", "ssh"},
		{2222, "SSH-Alt", "ssh"},

		// Email - direct TLS
		{993, "IMAPS", "tls"},
		{995, "POP3S", "tls"},
		{465, "SMTPS", "tls"},

		// Email - STARTTLS
		{25, "SMTP", "starttls-smtp"},
		{587, "SMTP-Submission", "starttls-smtp"},
		{143, "IMAP", "starttls-imap"},
		{110, "POP3", "starttls-pop3"},

		// Database TLS
		{5432, "PostgreSQL", "tls"},
		{3306, "MySQL", "tls"},

		// Other TLS services
		{636, "LDAPS", "tls"},
		{853, "DNS-over-TLS", "tls"},
		{3389, "RDP", "tls"},
	}
}

func ScanTarget(ctx context.Context, target string) ([]ScanResult, error) {
	ports := getDefaultPorts()
	var results []ScanResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	red := color.New(color.FgRed)

	cyan.Printf("  Scanning %d ports on %s...\n\n", len(ports), target)

	// Check which ports are open first (fast TCP connect scan)
	openPorts := findOpenPorts(ctx, target, ports)

	if len(openPorts) == 0 {
		return nil, fmt.Errorf("no open ports found on %s", target)
	}

	cyan.Printf("  Found %d open ports: ", len(openPorts))
	for i, p := range openPorts {
		if i > 0 {
			fmt.Print(", ")
		}
		fmt.Printf("%d/%s", p.Port, p.Service)
	}
	fmt.Println("\n")

	// Scan each open port
	for _, portDef := range openPorts {
		wg.Add(1)
		go func(pd PortDef) {
			defer wg.Done()

			var result *ScanResult
			var err error

			switch pd.Type {
			case "tls":
				result, err = scanTLSEndpoint(ctx, target, pd.Port)
			case "ssh":
				result, err = scanSSHEndpoint(ctx, target, pd.Port)
			case "starttls-smtp":
				result, err = scanSTARTTLS_SMTP(ctx, target, pd.Port)
			case "starttls-imap":
				result, err = scanSTARTTLS_IMAP(ctx, target, pd.Port)
			case "starttls-pop3":
				result, err = scanSTARTTLS_POP3(ctx, target, pd.Port)
			}

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				// Log failed scan but don't add to results
				red.Printf("  ✗ %s:%d/%s — %v\n", target, pd.Port, pd.Service, err)
				return
			}

			if result != nil {
				result.Service = pd.Service
				results = append(results, *result)
				if strings.Contains(result.RiskLevel, "CRITICAL") {
					red.Printf("  ✗ %s:%d/%s — %s [CRITICAL]\n",
						target, pd.Port, pd.Service, result.CipherSuite)
				} else if result.RiskLevel == "SAFE" {
					green.Printf("  ✓ %s:%d/%s — %s [SAFE]\n",
						target, pd.Port, pd.Service, result.CipherSuite)
				}
			}
		}(portDef)
	}

	wg.Wait()
	fmt.Println()

	if len(results) == 0 {
		return nil, fmt.Errorf("could not analyze any services on %s", target)
	}

	return results, nil
}

// Fast TCP connect scan to find open ports
func findOpenPorts(ctx context.Context, host string, ports []PortDef) []PortDef {
	var open []PortDef
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, pd := range ports {
		wg.Add(1)
		go func(p PortDef) {
			defer wg.Done()

			address := fmt.Sprintf("%s:%d", host, p.Port)
			conn, err := net.DialTimeout("tcp", address, 2*time.Second)
			if err != nil {
				return
			}
			conn.Close()

			mu.Lock()
			open = append(open, p)
			mu.Unlock()
		}(pd)
	}

	wg.Wait()
	return open
}

// ==========================================
// TLS SCANNER
// ==========================================

func scanTLSEndpoint(ctx context.Context, host string, port int) (*ScanResult, error) {
	address := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}

	// Try with certificate verification first
	conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS10,
		ServerName:         host,
	})

	certVerified := true

	if err != nil {
		// Retry without verification
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			ServerName:         host,
		})
		if err != nil {
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		certVerified = false
	}
	defer conn.Close()

	state := conn.ConnectionState()
	suiteName := tls.CipherSuiteName(state.CipherSuite)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      tlsVersionName(state.Version),
		CipherSuite:   suiteName,
		KeyExchange:   extractKeyExchange(suiteName),
		RiskLevel:     classifyRisk(suiteName),
		QuantumThreat: classifyQuantumThreat(suiteName),
		Remediation:   getRemediation(suiteName),
	}

	if !certVerified {
		result.Error = "Certificate verification failed"
	}

	// Extract certificate info
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = CertInfo{
			Subject:      cert.Subject.CommonName,
			Issuer:       cert.Issuer.CommonName,
			KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			SignatureAlg: cert.SignatureAlgorithm.String(),
			NotAfter:     cert.NotAfter,
			SANs:         cert.DNSNames,
		}

		// Extract key size based on key type
		switch pub := cert.PublicKey.(type) {
		case interface{ Size() int }:
			result.Certificate.KeySize = pub.Size() * 8
		default:
			_ = pub
		}
	}

	return result, nil
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	case 0x0300:
		return "SSL 3.0"
	default:
		return fmt.Sprintf("Unknown (0x%04x)", version)
	}
}

// ==========================================
// SSH SCANNER
// ==========================================

func scanSSHEndpoint(ctx context.Context, host string, port int) (*ScanResult, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	// Connect with timeout
	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("SSH connection failed: %w", err)
	}
	defer conn.Close()

	// Set read deadline
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read SSH banner
	banner := make([]byte, 256)
	n, err := conn.Read(banner)
	if err != nil {
		return nil, fmt.Errorf("failed to read SSH banner: %w", err)
	}
	sshBanner := strings.TrimSpace(string(banner[:n]))

	// Now do a proper SSH handshake to extract algorithms
	// Reconnect because we consumed the banner
	conn.Close()

	conn2, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("SSH reconnection failed: %w", err)
	}
	defer conn2.Close()
	conn2.SetDeadline(time.Now().Add(10 * time.Second))

	// Use Go's SSH library to perform key exchange
	// We'll use a custom host key callback to capture the host key type
	var hostKeyType string
	var hostKeySize int

	sshConfig := &ssh.ClientConfig{
		User: "pqscan-probe",
		Auth: []ssh.AuthMethod{
			// No auth - we just want the key exchange
			ssh.Password(""),
		},
		HostKeyCallback: func(hostname string, remote net.Addr, key ssh.PublicKey) error {
			hostKeyType = key.Type()
			// Try to get key size from the marshaled key
			marshaled := key.Marshal()
			hostKeySize = len(marshaled) * 8 // rough estimate
			return nil
		},
		Timeout: 5 * time.Second,
		Config: ssh.Config{
			// Request all algorithms to see what server supports
			KeyExchanges: []string{
				"sntrup761x25519-sha512@openssh.com", // PQC hybrid!
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group18-sha512",
				"diffie-hellman-group14-sha256",
				"diffie-hellman-group14-sha1",
			},
		},
	}

	// Attempt SSH handshake - it will fail at auth but we get the key exchange
	c, chans, reqs, err := ssh.NewClientConn(conn2, address, sshConfig)
	if c != nil {
		// We shouldn't get here, but clean up if we do
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
		c.Close()
	}

	// The error is expected (auth failure) - but we got what we needed
	// from the HostKeyCallback

	// Determine quantum risk based on host key type
	keyExchange := "curve25519-sha256" // most common default
	quantumThreat := "Shor's Algorithm — Key exchange BROKEN"
	riskLevel := "CRITICAL"
	remediation := "Enable sntrup761x25519-sha512@openssh.com (hybrid PQC key exchange in OpenSSH 9.x)"

	// Check if server supports PQC key exchange
	if hostKeyType == "" {
		hostKeyType = "unknown"
	}

	// Check for PQC-safe host key
	if strings.Contains(hostKeyType, "sntrup") ||
		strings.Contains(hostKeyType, "mlkem") {
		riskLevel = "SAFE"
		quantumThreat = "None — Post-Quantum hybrid key exchange"
		remediation = "No action needed — already using PQC"
	}

	hostKeyRisk := classifySSHHostKey(hostKeyType)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      sshBanner,
		Service:       "SSH",
		CipherSuite:   fmt.Sprintf("HostKey: %s", hostKeyType),
		KeyExchange:   keyExchange,
		RiskLevel:     riskLevel,
		QuantumThreat: quantumThreat,
		Remediation:   remediation,
		Certificate: CertInfo{
			Subject:      host,
			KeyAlgorithm: hostKeyType,
			KeySize:      hostKeySize,
			SignatureAlg: hostKeyRisk,
		},
	}

	return result, nil
}

func classifySSHHostKey(keyType string) string {
	switch {
	case strings.Contains(keyType, "ssh-rsa"):
		return "CRITICAL — RSA broken by Shor's algorithm"
	case strings.Contains(keyType, "ecdsa"):
		return "CRITICAL — ECDSA broken by Shor's algorithm"
	case strings.Contains(keyType, "ssh-ed25519"):
		return "CRITICAL — Ed25519 broken by Shor's algorithm"
	case strings.Contains(keyType, "ssh-dss"):
		return "CRITICAL — DSA broken classically AND by Shor's"
	case strings.Contains(keyType, "sntrup"):
		return "SAFE — Post-quantum hybrid key"
	case strings.Contains(keyType, "mlkem"):
		return "SAFE — Post-quantum key encapsulation"
	default:
		return "UNKNOWN — Manual review needed"
	}
}

// ==========================================
// STARTTLS SCANNERS
// ==========================================

func scanSTARTTLS_SMTP(ctx context.Context, host string, port int) (*ScanResult, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("SMTP connection failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// Read greeting
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read SMTP banner: %w", err)
	}
	greeting := string(buf[:n])

	if !strings.HasPrefix(greeting, "220") {
		return nil, fmt.Errorf("unexpected SMTP greeting: %s", greeting)
	}

	// Send EHLO
	fmt.Fprintf(conn, "EHLO pqscan.local\r\n")
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("EHLO failed: %w", err)
	}
	ehloResponse := string(buf[:n])

	// Check if STARTTLS is supported
	if !strings.Contains(strings.ToUpper(ehloResponse), "STARTTLS") {
		return &ScanResult{
			Host:          host,
			Port:          port,
			Protocol:      "SMTP (NO STARTTLS)",
			Service:       "SMTP",
			CipherSuite:   "NONE — Plaintext only",
			KeyExchange:   "None",
			RiskLevel:     "CRITICAL (classically broken AND quantum broken)",
			QuantumThreat: "N/A — No encryption at all",
			Remediation:   "Enable STARTTLS on SMTP server immediately",
		}, nil
	}

	// Send STARTTLS
	fmt.Fprintf(conn, "STARTTLS\r\n")
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("STARTTLS command failed: %w", err)
	}
	response := string(buf[:n])

	if !strings.HasPrefix(response, "220") {
		return nil, fmt.Errorf("STARTTLS rejected: %s", response)
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})

	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake after STARTTLS failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	suiteName := tls.CipherSuiteName(state.CipherSuite)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      fmt.Sprintf("SMTP STARTTLS → %s", tlsVersionName(state.Version)),
		CipherSuite:   suiteName,
		KeyExchange:   extractKeyExchange(suiteName),
		RiskLevel:     classifyRisk(suiteName),
		QuantumThreat: classifyQuantumThreat(suiteName),
		Remediation:   getRemediation(suiteName),
	}

	// Extract certificate
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = CertInfo{
			Subject:      cert.Subject.CommonName,
			Issuer:       cert.Issuer.CommonName,
			KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			SignatureAlg: cert.SignatureAlgorithm.String(),
			NotAfter:     cert.NotAfter,
			SANs:         cert.DNSNames,
		}
		switch pub := cert.PublicKey.(type) {
		case interface{ Size() int }:
			result.Certificate.KeySize = pub.Size() * 8
		default:
			_ = pub
		}
	}

	return result, nil
}

func scanSTARTTLS_IMAP(ctx context.Context, host string, port int) (*ScanResult, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("IMAP connection failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 1024)

	// Read greeting
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read IMAP greeting: %w", err)
	}
	greeting := string(buf[:n])

	if !strings.Contains(greeting, "OK") {
		return nil, fmt.Errorf("unexpected IMAP greeting: %s", greeting)
	}

	// Check capability
	fmt.Fprintf(conn, "a001 CAPABILITY\r\n")
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("CAPABILITY failed: %w", err)
	}
	capResponse := string(buf[:n])

	if !strings.Contains(strings.ToUpper(capResponse), "STARTTLS") {
		return &ScanResult{
			Host:          host,
			Port:          port,
			Protocol:      "IMAP (NO STARTTLS)",
			Service:       "IMAP",
			CipherSuite:   "NONE — Plaintext only",
			KeyExchange:   "None",
			RiskLevel:     "CRITICAL (classically broken AND quantum broken)",
			QuantumThreat: "N/A — No encryption at all",
			Remediation:   "Enable STARTTLS on IMAP server",
		}, nil
	}

	// Send STARTTLS
	fmt.Fprintf(conn, "a002 STARTTLS\r\n")
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("STARTTLS failed: %w", err)
	}
	response := string(buf[:n])

	if !strings.Contains(response, "OK") {
		return nil, fmt.Errorf("STARTTLS rejected: %s", response)
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})

	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	suiteName := tls.CipherSuiteName(state.CipherSuite)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      fmt.Sprintf("IMAP STARTTLS → %s", tlsVersionName(state.Version)),
		CipherSuite:   suiteName,
		KeyExchange:   extractKeyExchange(suiteName),
		RiskLevel:     classifyRisk(suiteName),
		QuantumThreat: classifyQuantumThreat(suiteName),
		Remediation:   getRemediation(suiteName),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = CertInfo{
			Subject:      cert.Subject.CommonName,
			Issuer:       cert.Issuer.CommonName,
			KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			SignatureAlg: cert.SignatureAlgorithm.String(),
			NotAfter:     cert.NotAfter,
			SANs:         cert.DNSNames,
		}
		switch pub := cert.PublicKey.(type) {
		case interface{ Size() int }:
			result.Certificate.KeySize = pub.Size() * 8
		default:
			_ = pub
		}
	}

	return result, nil
}

func scanSTARTTLS_POP3(ctx context.Context, host string, port int) (*ScanResult, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	conn, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("POP3 connection failed: %w", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 1024)

	// Read greeting
	n, err := conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read POP3 greeting: %w", err)
	}
	greeting := string(buf[:n])

	if !strings.HasPrefix(greeting, "+OK") {
		return nil, fmt.Errorf("unexpected POP3 greeting: %s", greeting)
	}

	// Send STLS
	fmt.Fprintf(conn, "STLS\r\n")
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("STLS failed: %w", err)
	}
	response := string(buf[:n])

	if !strings.HasPrefix(response, "+OK") {
		return &ScanResult{
			Host:          host,
			Port:          port,
			Protocol:      "POP3 (NO STARTTLS)",
			Service:       "POP3",
			CipherSuite:   "NONE — Plaintext only",
			KeyExchange:   "None",
			RiskLevel:     "CRITICAL (classically broken AND quantum broken)",
			QuantumThreat: "N/A — No encryption at all",
			Remediation:   "Enable STLS on POP3 server",
		}, nil
	}

	// Upgrade to TLS
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})

	err = tlsConn.Handshake()
	if err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	suiteName := tls.CipherSuiteName(state.CipherSuite)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      fmt.Sprintf("POP3 STLS → %s", tlsVersionName(state.Version)),
		CipherSuite:   suiteName,
		KeyExchange:   extractKeyExchange(suiteName),
		RiskLevel:     classifyRisk(suiteName),
		QuantumThreat: classifyQuantumThreat(suiteName),
		Remediation:   getRemediation(suiteName),
	}

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Certificate = CertInfo{
			Subject:      cert.Subject.CommonName,
			Issuer:       cert.Issuer.CommonName,
			KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
			SignatureAlg: cert.SignatureAlgorithm.String(),
			NotAfter:     cert.NotAfter,
			SANs:         cert.DNSNames,
		}
		switch pub := cert.PublicKey.(type) {
		case interface{ Size() int }:
			result.Certificate.KeySize = pub.Size() * 8
		default:
			_ = pub
		}
	}

	return result, nil
}