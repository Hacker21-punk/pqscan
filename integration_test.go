package main

import (
	"bufio"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// generateCert produces a self-signed tls.Certificate and its parsed x509.Certificate
func generateCert(priv crypto.PrivateKey, pub crypto.PublicKey) (tls.Certificate, *x509.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "127.0.0.1",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	x509Cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  priv,
	}

	return tlsCert, x509Cert, nil
}

// TestCertKeySizes verifies that extractCertInfo correctly determines the key sizes
// for RSA-2048, ECDSA P-256, and Ed25519 certificates (ensuring no regression of the 0-bit bug).
func TestCertKeySizes(t *testing.T) {
	// RSA-2048
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	_, rsaCert, err := generateCert(rsaPriv, &rsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to create RSA cert: %v", err)
	}

	// ECDSA P-256
	ecdsaPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	_, ecdsaCert, err := generateCert(ecdsaPriv, &ecdsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to create ECDSA cert: %v", err)
	}

	// Ed25519
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	_, edCert, err := generateCert(edPriv, edPub)
	if err != nil {
		t.Fatalf("failed to create Ed25519 cert: %v", err)
	}

	tests := []struct {
		name     string
		cert     *x509.Certificate
		wantSize int
		wantAlg  string
	}{
		{"RSA-2048", rsaCert, 2048, "RSA"},
		{"ECDSA P-256", ecdsaCert, 256, "ECDSA"},
		{"Ed25519", edCert, 256, "Ed25519"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			info := extractCertInfo(tc.cert)
			if info.KeySize != tc.wantSize {
				t.Errorf("extractCertInfo KeySize = %d, want %d", info.KeySize, tc.wantSize)
			}
			if !strings.Contains(info.KeyAlgorithm, tc.wantAlg) {
				t.Errorf("extractCertInfo KeyAlgorithm = %q, want to contain %q", info.KeyAlgorithm, tc.wantAlg)
			}
		})
	}
}

// TestTLSPathways runs table-driven tests checking both the PQC-safe pathway (which
// negotiates ML-KEM by default) and the HNDL-exposed pathway (where only classical curves are supported).
func TestTLSPathways(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	tlsCert, _, err := generateCert(rsaPriv, &rsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to generate TLS cert: %v", err)
	}

	tests := []struct {
		name      string
		forceHNDL bool
		wantRisk  string
	}{
		{
			name:      "PQC Safe Pathway",
			forceHNDL: false,
			wantRisk:  RiskSafe,
		},
		{
			name:      "Classical HNDL Pathway",
			forceHNDL: true,
			wantRisk:  RiskHNDL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := &tls.Config{
				Certificates: []tls.Certificate{tlsCert},
			}
			if tc.forceHNDL {
				// Force only classical curve (X25519) so ML-KEM cannot be negotiated
				serverConfig.CurvePreferences = []tls.CurveID{tls.X25519}
			}

			ln, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
			if err != nil {
				t.Fatalf("failed to listen: %v", err)
			}
			defer ln.Close()

			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						if tcConn, ok := c.(*tls.Conn); ok {
							_ = tcConn.Handshake()
						}
					}(conn)
				}
			}()

			_, portStr, err := net.SplitHostPort(ln.Addr().String())
			if err != nil {
				t.Fatalf("failed to split host/port: %v", err)
			}
			var port int
			fmt.Sscanf(portStr, "%d", &port)

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			res, err := scanTLSEndpoint(ctx, "127.0.0.1", port)
			if err != nil {
				t.Fatalf("scanTLSEndpoint failed: %v", err)
			}

			if res.RiskLevel != tc.wantRisk {
				t.Errorf("expected RiskLevel %q, got %q (KEX: %q)", tc.wantRisk, res.RiskLevel, res.KeyExchange)
			}
		})
	}
}

// buildKexInitPacket constructs a raw binary SSH_MSG_KEXINIT packet containing custom key exchanges
func buildKexInitPacket(kexAlgos string) []byte {
	var payload []byte
	payload = append(payload, 20) // SSH_MSG_KEXINIT
	cookie := make([]byte, 16)
	payload = append(payload, cookie...)

	appendStr := func(s string) {
		length := uint32(len(s))
		var lenBuf [4]byte
		binary.BigEndian.PutUint32(lenBuf[:], length)
		payload = append(payload, lenBuf[:]...)
		payload = append(payload, []byte(s)...)
	}

	appendStr(kexAlgos)                  // kex_algorithms
	appendStr("ssh-ed25519,ssh-rsa")     // server_host_key_algorithms
	appendStr("aes128-ctr,aes256-ctr")   // encryption_algorithms_client_to_server
	appendStr("aes128-ctr,aes256-ctr")   // encryption_algorithms_server_to_client
	appendStr("hmac-sha2-256")           // mac_algorithms_client_to_server
	appendStr("hmac-sha2-256")           // mac_algorithms_server_to_client
	appendStr("none")                    // compression_algorithms_client_to_server
	appendStr("none")                    // compression_algorithms_server_to_client
	appendStr("")                        // languages_client_to_server
	appendStr("")                        // languages_server_to_client
	payload = append(payload, 0)          // first_kex_packet_follows (false)
	payload = append(payload, 0, 0, 0, 0) // reserved (uint32)

	payloadLen := len(payload)
	paddingLen := 4
	for (1+payloadLen+paddingLen)%8 != 0 {
		paddingLen++
	}

	pktLen := uint32(1 + payloadLen + paddingLen)
	var pktLenBuf [4]byte
	binary.BigEndian.PutUint32(pktLenBuf[:], pktLen)

	var packet []byte
	packet = append(packet, pktLenBuf[:]...)
	packet = append(packet, byte(paddingLen))
	packet = append(packet, payload...)
	packet = append(packet, make([]byte, paddingLen)...)

	return packet
}

// startMockSSHServer stands up a mock SSH server that expects two connections sequentially
func startMockSSHServer(t *testing.T, kexAlgos string) (int, func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	go func() {
		// Connection 1 (Phase 1: probeSSHKexAlgorithms)
		conn1, err := ln.Accept()
		if err == nil {
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-MockSSHServer\r\n"))
				reader := bufio.NewReader(c)
				_, _ = reader.ReadString('\n')
				packet := buildKexInitPacket(kexAlgos)
				_, _ = c.Write(packet)
			}(conn1)
		}

		// Connection 2 (Phase 2: full handshake reconnect)
		conn2, err := ln.Accept()
		if err == nil {
			go func(c net.Conn) {
				defer c.Close()
				_, _ = c.Write([]byte("SSH-2.0-MockSSHServer\r\n"))
				reader := bufio.NewReader(c)
				_, _ = reader.ReadString('\n')
			}(conn2)
		}
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}
	var port int
	fmt.Sscanf(portStr, "%d", &port)

	return port, func() { ln.Close() }
}

// TestSSHPathways runs table-driven tests checking both the PQC-advertised pathway
// and the classical-only pathway.
func TestSSHPathways(t *testing.T) {
	tests := []struct {
		name     string
		kexAlgos string
		wantRisk string
	}{
		{
			name:     "SSH PQC Pathway",
			kexAlgos: "sntrup761x25519-sha512@openssh.com,curve25519-sha256",
			wantRisk: RiskSafe,
		},
		{
			name:     "SSH Classical Pathway",
			kexAlgos: "curve25519-sha256,diffie-hellman-group14-sha256",
			wantRisk: RiskHNDL,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			port, cleanup := startMockSSHServer(t, tc.kexAlgos)
			defer cleanup()

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()

			res, err := scanSSHEndpoint(ctx, "127.0.0.1", port)
			if err != nil {
				t.Fatalf("scanSSHEndpoint failed: %v", err)
			}

			if res.RiskLevel != tc.wantRisk {
				t.Errorf("expected RiskLevel %q, got %q (KEX: %q)", tc.wantRisk, res.RiskLevel, res.KeyExchange)
			}
		})
	}
}

// TestSTARTTLSFragmentation stands up fake SMTP and IMAP servers that deliberately write
// their multi-line responses in several small connection writes separated by tiny sleeps.
// This acts as a regression test to verify our buffered line-by-line assembly logic.
func TestSTARTTLSFragmentation(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	tlsCert, _, err := generateCert(rsaPriv, &rsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to generate TLS cert: %v", err)
	}
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	t.Run("SMTP STARTTLS Fragmentation", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Write greeting in fragments
			_, _ = conn.Write([]byte("220 SMTP "))
			time.Sleep(10 * time.Millisecond)
			_, _ = conn.Write([]byte("server ready\r\n"))

			// Read EHLO
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if !strings.HasPrefix(string(buf[:n]), "EHLO") {
				return
			}

			// Write EHLO response in multiple fragmented packets with sleep
			_, _ = conn.Write([]byte("250-mail.example.com\r\n"))
			time.Sleep(15 * time.Millisecond)
			_, _ = conn.Write([]byte("250-STARTTLS\r\n250-8BITMIME\r\n"))
			time.Sleep(15 * time.Millisecond)
			_, _ = conn.Write([]byte("250 OK\r\n"))

			// Read STARTTLS
			n, _ = conn.Read(buf)
			if !strings.HasPrefix(string(buf[:n]), "STARTTLS") {
				return
			}

			// Write 220
			_, _ = conn.Write([]byte("220 Ready "))
			time.Sleep(10 * time.Millisecond)
			_, _ = conn.Write([]byte("to start TLS\r\n"))

			// TLS handshake
			tlsConn := tls.Server(conn, serverConfig)
			_ = tlsConn.Handshake()
		}()

		_, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("failed to split host/port: %v", err)
		}
		var port int
		fmt.Sscanf(portStr, "%d", &port)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		res, err := scanSTARTTLS_SMTP(ctx, "127.0.0.1", port)
		if err != nil {
			t.Fatalf("scanSTARTTLS_SMTP failed: %v", err)
		}

		if isCritical(res.RiskLevel) {
			t.Errorf("expected SMTP STARTTLS to negotiate successfully (non-critical), got %s", res.RiskLevel)
		}
	})

	t.Run("IMAP STARTTLS Fragmentation", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("failed to listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Write greeting
			_, _ = conn.Write([]byte("* OK IMAP4"))
			time.Sleep(10 * time.Millisecond)
			_, _ = conn.Write([]byte("rev1 Server Ready\r\n"))

			// Read CAPABILITY
			buf := make([]byte, 1024)
			n, _ := conn.Read(buf)
			if !strings.Contains(string(buf[:n]), "CAPABILITY") {
				return
			}

			// Write CAPABILITY response in multiple fragmented packets
			_, _ = conn.Write([]byte("* CAPABILITY IMAP4rev1"))
			time.Sleep(15 * time.Millisecond)
			_, _ = conn.Write([]byte(" STARTTLS LOGINDISABLED\r\n"))
			time.Sleep(15 * time.Millisecond)
			_, _ = conn.Write([]byte("a001 OK CAPABILITY completed\r\n"))

			// Read STARTTLS
			n, _ = conn.Read(buf)
			if !strings.Contains(string(buf[:n]), "STARTTLS") {
				return
			}

			// Write tagged OK response matching client's "a002 STARTTLS\r\n"
			_, _ = conn.Write([]byte("a002 OK Begin "))
			time.Sleep(10 * time.Millisecond)
			_, _ = conn.Write([]byte("TLS negotiation now\r\n"))

			// TLS handshake
			tlsConn := tls.Server(conn, serverConfig)
			_ = tlsConn.Handshake()
		}()

		_, portStr, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatalf("failed to split host/port: %v", err)
		}
		var port int
		fmt.Sscanf(portStr, "%d", &port)

		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()

		res, err := scanSTARTTLS_IMAP(ctx, "127.0.0.1", port)
		if err != nil {
			t.Fatalf("scanSTARTTLS_IMAP failed: %v", err)
		}

		if isCritical(res.RiskLevel) {
			t.Errorf("expected IMAP STARTTLS to negotiate successfully (non-critical), got %s", res.RiskLevel)
		}
	})
}

// TestPanicIsolation verifies that if one target/port scan panics, the batch scan
// successfully completes and collects findings for other targets/ports.
func TestPanicIsolation(t *testing.T) {
	// Stand up a valid local TLS listener (Port A)
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	tlsCert, _, err := generateCert(rsaPriv, &rsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("failed to generate TLS cert: %v", err)
	}
	serverConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
	}

	lnA, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer lnA.Close()

	go func() {
		for {
			conn, err := lnA.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tcConn, ok := c.(*tls.Conn); ok {
					_ = tcConn.Handshake()
				}
			}(conn)
		}
	}()

	_, portStrA, err := net.SplitHostPort(lnA.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}
	var portA int
	fmt.Sscanf(portStrA, "%d", &portA)

	// Stand up a second valid local TLS listener (Port B) which we will force to panic
	lnB, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	if err != nil {
		t.Fatalf("tls.Listen failed: %v", err)
	}
	defer lnB.Close()

	go func() {
		for {
			conn, err := lnB.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tcConn, ok := c.(*tls.Conn); ok {
					_ = tcConn.Handshake()
				}
			}(conn)
		}
	}()

	_, portStrB, err := net.SplitHostPort(lnB.Addr().String())
	if err != nil {
		t.Fatalf("failed to split host/port: %v", err)
	}
	var portB int
	fmt.Sscanf(portStrB, "%d", &portB)

	// Override ports to scan to contain both portA and portB
	defaultPortsOverride = []PortDef{
		{Port: portA, Service: "HTTPS-Valid", Type: "tls"},
		{Port: portB, Service: "HTTPS-Panic", Type: "tls"},
	}
	defer func() { defaultPortsOverride = nil }()

	// Trigger a panic specifically when scanning Port B
	testHookPortScan = func(pd PortDef) {
		if pd.Port == portB {
			panic("simulated port panic")
		}
	}
	defer func() { testHookPortScan = nil }()

	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	results, err := ScanTarget(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("ScanTarget failed: %v", err)
	}

	// We expect only 1 result (from the valid Port A) because Port B panicked and recovered
	if len(results) != 1 {
		t.Errorf("expected 1 result, got %d", len(results))
	} else if results[0].Port != portA {
		t.Errorf("expected result to be for Port A (%d), got Port %d", portA, results[0].Port)
	}
}
