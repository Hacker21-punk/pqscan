package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
	"golang.org/x/crypto/ssh"
)

// --------------------------------------------------------------------------
// TLS helpers
// --------------------------------------------------------------------------

// classifyTLSConnection derives key-exchange description, risk level, quantum
// threat, and remediation from a completed TLS handshake.
//
// It checks state.CurveID FIRST — this is the only reliable way to detect
// a PQC hybrid key exchange in TLS 1.3, because TLS 1.3 cipher suite names
// (e.g. TLS_AES_256_GCM_SHA384) never encode the key-exchange group. The
// constants below match IANA TLS Named Groups registry values for the ML-KEM
// hybrids.  X25519MLKEM768 is exported by crypto/tls since Go 1.24; the NIST-
// curve variants are defined locally until the stdlib exports them.
const (
	curveSecP256r1MLKEM768  tls.CurveID = 4587 // IANA 0x11EB
	curveSecP384r1MLKEM1024 tls.CurveID = 4589 // IANA 0x11ED
)

func classifyTLSConnection(state tls.ConnectionState) (keyExchange, riskLevel, quantumThreat, remediation string) {
	switch state.CurveID {
	case tls.X25519MLKEM768:
		return "X25519+ML-KEM-768 (FIPS 203 hybrid)",
			RiskSafe,
			"None — X25519+ML-KEM-768 is post-quantum safe",
			"No action needed — already quantum safe"
	case curveSecP256r1MLKEM768:
		return "P-256+ML-KEM-768 (FIPS 203 hybrid)",
			RiskSafe,
			"None — P-256+ML-KEM-768 is post-quantum safe",
			"No action needed — already quantum safe"
	case curveSecP384r1MLKEM1024:
		return "P-384+ML-KEM-1024 (FIPS 203 hybrid)",
			RiskSafe,
			"None — P-384+ML-KEM-1024 is post-quantum safe",
			"No action needed — already quantum safe"
	}
	// Not a PQC hybrid — fall back to cipher suite name analysis.
	suite := tls.CipherSuiteName(state.CipherSuite)
	return extractKeyExchange(suite), classifyRisk(suite), classifyQuantumThreat(suite), getRemediation(suite)
}

// extractCertInfo builds a CertInfo from an x509.Certificate.
// It handles RSA, ECDSA, and Ed25519 key types correctly — unlike the
// former interface{ Size() int } type switch, which returned 0 bits for
// ECDSA and Ed25519 because neither type implements that interface.
func extractCertInfo(cert *x509.Certificate) CertInfo {
	info := CertInfo{
		Subject:      cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
		KeyAlgorithm: cert.PublicKeyAlgorithm.String(),
		SignatureAlg: cert.SignatureAlgorithm.String(),
		NotAfter:     cert.NotAfter,
		SANs:         cert.DNSNames,
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		info.KeySize = pub.N.BitLen()
	case *ecdsa.PublicKey:
		info.KeySize = pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		info.KeySize = 256
	default:
		_ = pub // PQC or unknown key type — size is not available
	}
	return info
}

// --------------------------------------------------------------------------
// SSH helpers
// --------------------------------------------------------------------------

// sshPQCKexAlgorithms is the canonical list of known PQC or PQC-hybrid SSH
// key exchange algorithms (per OpenSSH 9.0+ and IETF drafts, July 2026).
var sshPQCKexAlgorithms = map[string]string{
	"sntrup761x25519-sha512@openssh.com": "sntrup761x25519 (OpenSSH 9.0+ default)",
	"mlkem768x25519-sha256":               "ML-KEM-768+X25519 (OpenSSH 10.0+ default)",
	"mlkem768x25519-sha256@openssh.com":   "ML-KEM-768+X25519 (OpenSSH vendor)",
}

// testHookPortScan is a package-level test hook to simulate panics/behavior
// inside the concurrent ScanTarget port loop.
var testHookPortScan func(pd PortDef)

// probeSSHKexAlgorithms opens a raw TCP connection and parses the server's
// SSH_MSG_KEXINIT packet (RFC 4253 §7.1) to extract the server's advertised
// kex_algorithms name-list — before the Go SSH library takes over the
// connection. It also returns the SSH banner string.
//
// golang.org/x/crypto/ssh does not expose the negotiated KEX algorithm in
// its public API, so raw packet parsing is the only option that does not
// require a third-party library.
func probeSSHKexAlgorithms(ctx context.Context, host string, port int) (kexAlgos []string, banner string, err error) {
	address := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	} else {
		conn.SetDeadline(time.Now().Add(8 * time.Second))
	}

	reader := bufio.NewReader(conn)

	// RFC 4253 §4.2 — server sends its version string as the very first line.
	line, err := reader.ReadString('\n')
	if err != nil {
		return nil, "", fmt.Errorf("read SSH banner: %w", err)
	}
	banner = strings.TrimSpace(line)
	if !strings.HasPrefix(banner, "SSH-") {
		return nil, banner, fmt.Errorf("unexpected SSH banner: %q", banner)
	}

	// RFC 4253 §6: BinaryPacket = uint32(length) | byte(padding_len) | payload | padding
	// The server sends SSH_MSG_KEXINIT as its first binary packet immediately after the banner.
	var pktLenBuf [4]byte
	if _, err := io.ReadFull(reader, pktLenBuf[:]); err != nil {
		return nil, banner, fmt.Errorf("read KEXINIT packet length: %w", err)
	}
	pktLen := binary.BigEndian.Uint32(pktLenBuf[:])
	if pktLen < 2 || pktLen > 65535 {
		return nil, banner, fmt.Errorf("implausible KEXINIT packet length: %d", pktLen)
	}

	payload := make([]byte, pktLen)
	if _, err := io.ReadFull(reader, payload); err != nil {
		return nil, banner, fmt.Errorf("read KEXINIT payload: %w", err)
	}

	// payload[0]    = padding_length
	// payload[1]    = SSH_MSG_KEXINIT (must be 20)
	// payload[2:18] = 16-byte random cookie
	// payload[18:]  = series of name-lists, first is kex_algorithms
	if len(payload) < 20 {
		return nil, banner, fmt.Errorf("KEXINIT payload too short (%d bytes)", len(payload))
	}
	paddingLen := int(payload[0])
	if payload[1] != 20 {
		return nil, banner, fmt.Errorf("expected SSH_MSG_KEXINIT (20), got %d", payload[1])
	}

	const cookieOffset = 18 // 1 (padding_len) + 1 (msg_type) + 16 (cookie)
	dataEnd := len(payload) - paddingLen

	if cookieOffset+4 > dataEnd {
		return nil, banner, fmt.Errorf("KEXINIT too short for kex name-list length")
	}
	nameListLen := int(binary.BigEndian.Uint32(payload[cookieOffset : cookieOffset+4]))
	nameListStart := cookieOffset + 4

	if nameListStart+nameListLen > dataEnd {
		return nil, banner, fmt.Errorf("KEXINIT kex_algorithms name-list out of bounds")
	}
	kexStr := string(payload[nameListStart : nameListStart+nameListLen])
	if kexStr == "" {
		return nil, banner, nil
	}
	return strings.Split(kexStr, ","), banner, nil
}

// sshFindPQCKex returns the first PQC kex algorithm found in algos, or "".
func sshFindPQCKex(algos []string) string {
	for _, algo := range algos {
		if label, ok := sshPQCKexAlgorithms[algo]; ok {
			return label
		}
	}
	return ""
}

// --------------------------------------------------------------------------
// STARTTLS protocol helpers
// --------------------------------------------------------------------------

// readSMTPLines reads a complete SMTP multi-line response from a bufio.Reader.
// SMTP multi-line responses use "DDD-text" for continuation and "DDD text"
// (space after the code) for the final line. A single TCP read is unreliable
// because multi-line EHLO responses commonly span multiple TCP segments.
func readSMTPLines(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		sb.WriteString(line)
		if err != nil {
			return sb.String(), err
		}
		// A line of length ≥ 4 ending with "<code> " (space at pos 3) is the final line.
		if len(line) >= 4 && line[3] == ' ' {
			break
		}
	}
	return sb.String(), nil
}

// readIMAPLines reads a complete IMAP response sequence from a bufio.Reader.
// Untagged responses start with "*"; the tagged response ("a001 OK ...") ends
// the sequence. A single TCP read is unreliable for multi-line CAPABILITY responses.
func readIMAPLines(r *bufio.Reader) (string, error) {
	var sb strings.Builder
	for {
		line, err := r.ReadString('\n')
		sb.WriteString(line)
		if err != nil {
			return sb.String(), err
		}
		// Untagged lines start with "*"; anything else is a tagged (final) response.
		if !strings.HasPrefix(line, "*") {
			break
		}
	}
	return sb.String(), nil
}

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

// defaultPortsOverride allows integration tests to redirect port scanning
// to custom ephemeral ports on loopback.
var defaultPortsOverride []PortDef

func getDefaultPorts() []PortDef {
	if defaultPortsOverride != nil {
		return defaultPortsOverride
	}
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

			// Recover from any unexpected panic so one malformed server response
			// cannot abort the entire batch scan.
			defer func() {
				if r := recover(); r != nil {
					red.Printf("  ✗ %s:%d/%s — internal panic: %v\n",
						target, pd.Port, pd.Service, r)
				}
			}()

			if testHookPortScan != nil {
				testHookPortScan(pd)
			}

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
				switch {
				case isCritical(result.RiskLevel):
					red.Printf("  ✗ %s:%d/%s — %s [CRITICAL]\n",
						target, pd.Port, pd.Service, result.CipherSuite)
				case result.RiskLevel == RiskHNDL:
					red.Printf("  ⚠ %s:%d/%s — %s [HNDL-EXPOSED]\n",
						target, pd.Port, pd.Service, result.CipherSuite)
				case result.RiskLevel == RiskSafe:
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
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	var conn *tls.Conn
	certVerified := true

	if err == nil {
		conn = tls.Client(rawConn, &tls.Config{
			InsecureSkipVerify: false,
			MinVersion:         tls.VersionTLS10,
			ServerName:         host,
		})
		if d, ok := ctx.Deadline(); ok {
			conn.SetDeadline(d)
		} else {
			conn.SetDeadline(time.Now().Add(10 * time.Second))
		}
		err = conn.Handshake()
		if err != nil {
			rawConn.Close()
		}
	}

	if err != nil {
		// Retry without verification
		rawConn2, err2 := dialer.DialContext(ctx, "tcp", address)
		if err2 != nil {
			return nil, fmt.Errorf("connection failed: %w", err2)
		}
		conn = tls.Client(rawConn2, &tls.Config{
			InsecureSkipVerify: true,
			MinVersion:         tls.VersionTLS10,
			ServerName:         host,
		})
		if d, ok := ctx.Deadline(); ok {
			conn.SetDeadline(d)
		} else {
			conn.SetDeadline(time.Now().Add(10 * time.Second))
		}
		err = conn.Handshake()
		if err != nil {
			rawConn2.Close()
			return nil, fmt.Errorf("TLS handshake failed: %w", err)
		}
		certVerified = false
	}
	defer conn.Close()

	state := conn.ConnectionState()
	suiteName := tls.CipherSuiteName(state.CipherSuite)
	kexAlgo, riskLevel, quantumThreat, remediation := classifyTLSConnection(state)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      tlsVersionName(state.Version),
		CipherSuite:   suiteName,
		KeyExchange:   kexAlgo,
		RiskLevel:     riskLevel,
		QuantumThreat: quantumThreat,
		Remediation:   remediation,
	}

	if !certVerified {
		result.Error = "Certificate verification failed"
	}

	if len(state.PeerCertificates) > 0 {
		result.Certificate = extractCertInfo(state.PeerCertificates[0])
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

	// Phase 1: Raw TCP probe to read the server's SSH_MSG_KEXINIT packet.
	// golang.org/x/crypto/ssh does not expose the negotiated KEX algorithm in
	// its public API, so we parse the raw packet before the library takes over.
	serverKexAlgos, sshBanner, err := probeSSHKexAlgorithms(ctx, host, port)
	if err != nil {
		return nil, fmt.Errorf("SSH KEXINIT probe failed: %w", err)
	}

	// Phase 2: Full SSH handshake (via the Go library) for host-key extraction.
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn2, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("SSH reconnection failed: %w", err)
	}
	defer conn2.Close()
	if d, ok := ctx.Deadline(); ok {
		conn2.SetDeadline(d)
	} else {
		conn2.SetDeadline(time.Now().Add(10 * time.Second))
	}

	var hostKeyType string
	var hostKeySize int

	sshConfig := &ssh.ClientConfig{
		User: "pqscan-probe",
		Auth: []ssh.AuthMethod{ssh.Password("")},
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			hostKeyType = key.Type()
			hostKeySize = len(key.Marshal()) * 8 // rough estimate from wire encoding
			return nil
		},
		Timeout: 5 * time.Second,
		Config: ssh.Config{
			KeyExchanges: []string{
				"sntrup761x25519-sha512@openssh.com",
				"mlkem768x25519-sha256",
				"curve25519-sha256",
				"curve25519-sha256@libssh.org",
				"ecdh-sha2-nistp256",
				"ecdh-sha2-nistp384",
				"ecdh-sha2-nistp521",
				"diffie-hellman-group-exchange-sha256",
				"diffie-hellman-group16-sha512",
				"diffie-hellman-group14-sha256",
			},
		},
	}

	// Auth failure is expected — we only care about what the handshake reveals.
	c, chans, reqs, _ := ssh.NewClientConn(conn2, address, sshConfig)
	if c != nil {
		go ssh.DiscardRequests(reqs)
		go func() {
			for range chans {
			}
		}()
		c.Close()
	}

	if hostKeyType == "" {
		hostKeyType = "unknown"
	}

	// Classify based on the server's ADVERTISED kex algorithm list (from Phase 1).
	// This is the correct signal: host-key type (ssh-ed25519, ssh-rsa, etc.) is
	// independent of key exchange and will never contain PQC kex names.
	var riskLevel, quantumThreat, keyExchange, remediation string

	if pqcLabel := sshFindPQCKex(serverKexAlgos); pqcLabel != "" {
		riskLevel = RiskSafe
		quantumThreat = "None — server advertises PQC hybrid key exchange"
		keyExchange = pqcLabel
		remediation = "No action needed — server already supports PQC KEX"
	} else {
		riskLevel = RiskHNDL
		quantumThreat = "Shor's algorithm breaks all advertised key exchanges (Harvest Now, Decrypt Later)"
		if len(serverKexAlgos) > 0 {
			keyExchange = serverKexAlgos[0] // server's preferred (highest priority) algorithm
		} else {
			keyExchange = "unknown"
		}
		remediation = "Upgrade to OpenSSH 9.0+ and enable sntrup761x25519-sha512 / mlkem768x25519-sha256"
	}

	hostKeyRisk := classifySSHHostKey(hostKeyType)

	return &ScanResult{
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
	}, nil
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

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("SMTP connection failed: %w", err)
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	// Use a buffered reader so multi-line EHLO responses (which commonly span
	// multiple TCP segments) are read completely and not truncated.
	reader := bufio.NewReader(conn)

	// Read greeting (single line)
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read SMTP banner: %w", err)
	}
	if !strings.HasPrefix(greeting, "220") {
		return nil, fmt.Errorf("unexpected SMTP greeting: %s", strings.TrimSpace(greeting))
	}

	// Send EHLO and read the full multi-line response
	fmt.Fprintf(conn, "EHLO pqscan.local\r\n")
	ehloResponse, err := readSMTPLines(reader)
	if err != nil {
		return nil, fmt.Errorf("EHLO failed: %w", err)
	}

	if !strings.Contains(strings.ToUpper(ehloResponse), "STARTTLS") {
		return &ScanResult{
			Host:          host,
			Port:          port,
			Protocol:      "SMTP (NO STARTTLS)",
			Service:       "SMTP",
			CipherSuite:   "NONE — Plaintext only",
			KeyExchange:   "None",
			RiskLevel:     RiskCritical,
			QuantumThreat: "No encryption — data transmitted in plaintext",
			Remediation:   "Enable STARTTLS on SMTP server immediately",
		}, nil
	}

	// Send STARTTLS and read the single-line 220 response
	fmt.Fprintf(conn, "STARTTLS\r\n")
	starttlsResp, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("STARTTLS command failed: %w", err)
	}
	if !strings.HasPrefix(starttlsResp, "220") {
		return nil, fmt.Errorf("STARTTLS rejected: %s", strings.TrimSpace(starttlsResp))
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake after SMTP STARTTLS failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	suiteName := tls.CipherSuiteName(state.CipherSuite)
	kexAlgo, riskLevel, quantumThreat, remediation := classifyTLSConnection(state)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      fmt.Sprintf("SMTP STARTTLS → %s", tlsVersionName(state.Version)),
		CipherSuite:   suiteName,
		KeyExchange:   kexAlgo,
		RiskLevel:     riskLevel,
		QuantumThreat: quantumThreat,
		Remediation:   remediation,
	}
	if len(state.PeerCertificates) > 0 {
		result.Certificate = extractCertInfo(state.PeerCertificates[0])
	}
	return result, nil
}

func scanSTARTTLS_IMAP(ctx context.Context, host string, port int) (*ScanResult, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("IMAP connection failed: %w", err)
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	// Use a buffered reader so multi-line CAPABILITY responses (which commonly
	// arrive across multiple TCP segments) are read completely.
	reader := bufio.NewReader(conn)

	// Read greeting — IMAP servers send a single untagged "* OK" line.
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read IMAP greeting: %w", err)
	}
	if !strings.Contains(greeting, "OK") {
		return nil, fmt.Errorf("unexpected IMAP greeting: %s", strings.TrimSpace(greeting))
	}

	// Request capabilities and read the full tagged response.
	fmt.Fprintf(conn, "a001 CAPABILITY\r\n")
	capResponse, err := readIMAPLines(reader)
	if err != nil {
		return nil, fmt.Errorf("CAPABILITY failed: %w", err)
	}

	if !strings.Contains(strings.ToUpper(capResponse), "STARTTLS") {
		return &ScanResult{
			Host:          host,
			Port:          port,
			Protocol:      "IMAP (NO STARTTLS)",
			Service:       "IMAP",
			CipherSuite:   "NONE — Plaintext only",
			KeyExchange:   "None",
			RiskLevel:     RiskCritical,
			QuantumThreat: "No encryption — data transmitted in plaintext",
			Remediation:   "Enable STARTTLS on IMAP server",
		}, nil
	}

	fmt.Fprintf(conn, "a002 STARTTLS\r\n")
	starttlsResp, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("IMAP STARTTLS command failed: %w", err)
	}
	if !strings.Contains(starttlsResp, "OK") {
		return nil, fmt.Errorf("IMAP STARTTLS rejected: %s", strings.TrimSpace(starttlsResp))
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake after IMAP STARTTLS failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	suiteName := tls.CipherSuiteName(state.CipherSuite)
	kexAlgo, riskLevel, quantumThreat, remediation := classifyTLSConnection(state)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      fmt.Sprintf("IMAP STARTTLS → %s", tlsVersionName(state.Version)),
		CipherSuite:   suiteName,
		KeyExchange:   kexAlgo,
		RiskLevel:     riskLevel,
		QuantumThreat: quantumThreat,
		Remediation:   remediation,
	}
	if len(state.PeerCertificates) > 0 {
		result.Certificate = extractCertInfo(state.PeerCertificates[0])
	}
	return result, nil
}

func scanSTARTTLS_POP3(ctx context.Context, host string, port int) (*ScanResult, error) {
	address := fmt.Sprintf("%s:%d", host, port)

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("POP3 connection failed: %w", err)
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		conn.SetDeadline(d)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}

	reader := bufio.NewReader(conn)

	// POP3 greeting is a single "+OK ..." line.
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("failed to read POP3 greeting: %w", err)
	}
	if !strings.HasPrefix(greeting, "+OK") {
		return nil, fmt.Errorf("unexpected POP3 greeting: %s", strings.TrimSpace(greeting))
	}

	// Send STLS and read single-line response.
	fmt.Fprintf(conn, "STLS\r\n")
	response, err := reader.ReadString('\n')
	if err != nil {
		return nil, fmt.Errorf("STLS command failed: %w", err)
	}

	if !strings.HasPrefix(response, "+OK") {
		return &ScanResult{
			Host:          host,
			Port:          port,
			Protocol:      "POP3 (NO STLS)",
			Service:       "POP3",
			CipherSuite:   "NONE — Plaintext only",
			KeyExchange:   "None",
			RiskLevel:     RiskCritical,
			QuantumThreat: "No encryption — data transmitted in plaintext",
			Remediation:   "Enable STLS on POP3 server",
		}, nil
	}

	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         host,
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake after POP3 STLS failed: %w", err)
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	suiteName := tls.CipherSuiteName(state.CipherSuite)
	kexAlgo, riskLevel, quantumThreat, remediation := classifyTLSConnection(state)

	result := &ScanResult{
		Host:          host,
		Port:          port,
		Protocol:      fmt.Sprintf("POP3 STLS → %s", tlsVersionName(state.Version)),
		CipherSuite:   suiteName,
		KeyExchange:   kexAlgo,
		RiskLevel:     riskLevel,
		QuantumThreat: quantumThreat,
		Remediation:   remediation,
	}
	if len(state.PeerCertificates) > 0 {
		result.Certificate = extractCertInfo(state.PeerCertificates[0])
	}
	return result, nil
}