import { useState } from 'react';

const scanners = [
  {
    id: 'tls',
    name: 'TLS/HTTPS',
    icon: '🔐',
    ports: '443, 8443',
    description: 'Full TLS 1.0-1.3 analysis with cipher suite enumeration, certificate chain inspection, and PQC key exchange detection.',
    capabilities: [
      'Protocol version detection (TLS 1.0-1.3)',
      'Cipher suite enumeration',
      'Certificate chain analysis',
      'Key exchange algorithm extraction',
      'PQC support probing (ML-KEM, X25519Kyber768)',
      'Supported curves and signature algorithms',
      'OCSP stapling and CT SCT detection',
    ],
    example: 'TLS_AES_256_GCM_SHA384 via ECDHE-P256',
  },
  {
    id: 'ssh',
    name: 'SSH',
    icon: '🖥️',
    ports: '22',
    description: 'SSH protocol analysis extracting key exchange algorithms, host keys, and symmetric ciphers without authentication.',
    capabilities: [
      'SSH protocol version detection',
      'Key exchange algorithm enumeration',
      'Host key algorithm detection',
      'Symmetric cipher analysis',
      'MAC algorithm extraction',
      'sntrup761x25519 hybrid PQC detection',
      'Compression algorithm listing',
    ],
    example: 'curve25519-sha256 with ssh-ed25519',
  },
  {
    id: 'ipsec',
    name: 'IPSec/IKE',
    icon: '🛡️',
    ports: 'UDP 500, 4500',
    description: 'IKEv1 and IKEv2 scanner for VPN endpoints. Extracts DH groups, encryption, and authentication methods.',
    capabilities: [
      'IKEv1 Main/Aggressive mode',
      'IKEv2 negotiation analysis',
      'DH group enumeration',
      'Encryption algorithm detection',
      'PRF/integrity algorithm extraction',
      'PPK (Post-quantum Preshared Key) detection',
      'NAT-T (NAT Traversal) support check',
    ],
    example: 'IKEv2 with DH-14, AES-256-GCM',
  },
  {
    id: 'starttls',
    name: 'STARTTLS',
    icon: '📧',
    ports: '25, 587, 143, 110',
    description: 'STARTTLS upgrade detection for SMTP, IMAP, POP3, FTP, LDAP, XMPP, PostgreSQL, and MySQL.',
    capabilities: [
      'SMTP STARTTLS (ports 25, 587)',
      'IMAP STARTTLS (port 143)',
      'POP3 STLS (port 110)',
      'FTP AUTH TLS (port 21)',
      'LDAP StartTLS (port 389)',
      'XMPP STARTTLS (port 5222)',
      'Database SSL (PostgreSQL, MySQL)',
    ],
    example: 'SMTP → TLS 1.2 → ECDHE-RSA-AES256',
  },
  {
    id: 'cert',
    name: 'Certificates',
    icon: '📜',
    ports: 'All TLS',
    description: 'Deep certificate analysis including chain validation, key algorithms, signature algorithms, and validity periods.',
    capabilities: [
      'Public key algorithm & size (RSA, EC, Ed25519)',
      'Signature algorithm analysis',
      'Full certificate chain extraction',
      'Validity period & expiration tracking',
      'SAN (Subject Alternative Names) extraction',
      'CA PQC readiness assessment',
      'Hybrid/composite certificate detection',
    ],
    example: 'RSA-2048 signed with sha256WithRSA',
  },
  {
    id: 'dns',
    name: 'DNS/DNSSEC',
    icon: '🌐',
    ports: '53, 853',
    description: 'DNSSEC cryptographic analysis, DANE/TLSA records, DKIM key extraction, and DoH/DoT endpoint scanning.',
    capabilities: [
      'DNSKEY algorithm analysis',
      'RRSIG signature validation',
      'DANE/TLSA record inspection',
      'CAA record checking',
      'DKIM public key extraction',
      'MTA-STS policy verification',
      'DoH/DoT endpoint scanning',
    ],
    example: 'DNSKEY RSA-2048 (Algorithm 8)',
  },
  {
    id: 'quic',
    name: 'QUIC/HTTP3',
    icon: '⚡',
    ports: 'UDP 443',
    description: 'QUIC protocol scanner for HTTP/3 endpoints with TLS 1.3 cryptographic parameter extraction.',
    capabilities: [
      'QUIC version negotiation',
      'TLS 1.3 within QUIC analysis',
      'Key exchange extraction',
      'Cipher suite detection',
      'Certificate analysis',
      'Connection migration support',
      'Early data (0-RTT) detection',
    ],
    example: 'QUIC v1 + TLS 1.3 AES-128-GCM',
  },
];

export default function Scanners() {
  const [activeScanner, setActiveScanner] = useState(scanners[0]);
  const [hoveredScanner, setHoveredScanner] = useState<string | null>(null);

  return (
    <section id="scanners" className="py-24 bg-slate-950 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-30" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section header */}
        <div className="text-center mb-16">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-purple-500/10 border border-purple-500/30 text-purple-400 text-sm font-medium mb-6">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 3.75H6A2.25 2.25 0 003.75 6v1.5M16.5 3.75H18A2.25 2.25 0 0120.25 6v1.5m0 9V18A2.25 2.25 0 0118 20.25h-1.5m-9 0H6A2.25 2.25 0 013.75 18v-1.5M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
            </svg>
            Protocol Scanners
          </span>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            7 Specialized <span className="text-purple-400">Scanners</span>
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Each protocol scanner is purpose-built to extract every cryptographic detail 
            from its target protocol. No stone left unturned.
          </p>
        </div>

        <div className="grid lg:grid-cols-12 gap-8">
          {/* Scanner tabs */}
          <div className="lg:col-span-4 space-y-2">
            {scanners.map((scanner) => (
              <button
                key={scanner.id}
                onClick={() => setActiveScanner(scanner)}
                onMouseEnter={() => setHoveredScanner(scanner.id)}
                onMouseLeave={() => setHoveredScanner(null)}
                className={`w-full p-4 rounded-xl border text-left transition-all duration-200 ${
                  activeScanner.id === scanner.id
                    ? 'bg-gradient-to-r from-purple-500/20 to-blue-500/20 border-purple-500/50 shadow-lg shadow-purple-500/10'
                    : 'bg-slate-800/30 border-slate-700/50 hover:bg-slate-800/60 hover:border-slate-600'
                }`}
              >
                <div className="flex items-center gap-4">
                  <span className="text-2xl">{scanner.icon}</span>
                  <div className="flex-1 min-w-0">
                    <div className="font-semibold text-white">{scanner.name}</div>
                    <div className="text-sm text-slate-500">Ports: {scanner.ports}</div>
                  </div>
                  <svg 
                    className={`w-5 h-5 text-slate-400 transition-transform ${
                      activeScanner.id === scanner.id || hoveredScanner === scanner.id ? 'translate-x-1' : ''
                    }`} 
                    fill="none" 
                    viewBox="0 0 24 24" 
                    stroke="currentColor" 
                    strokeWidth={2}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                  </svg>
                </div>
              </button>
            ))}
          </div>

          {/* Scanner detail */}
          <div className="lg:col-span-8">
            <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-8 backdrop-blur-sm h-full">
              <div className="flex items-start gap-4 mb-6">
                <span className="text-4xl">{activeScanner.icon}</span>
                <div>
                  <h3 className="text-2xl font-bold text-white mb-1">{activeScanner.name} Scanner</h3>
                  <div className="text-sm text-slate-500">Ports: {activeScanner.ports}</div>
                </div>
              </div>

              <p className="text-slate-400 mb-6">
                {activeScanner.description}
              </p>

              {/* Capabilities */}
              <div className="mb-6">
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Capabilities
                </h4>
                <div className="grid sm:grid-cols-2 gap-2">
                  {activeScanner.capabilities.map((capability, i) => (
                    <div key={i} className="flex items-start gap-2 text-sm text-slate-400">
                      <svg className="w-4 h-4 text-purple-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                      {capability}
                    </div>
                  ))}
                </div>
              </div>

              {/* Example output */}
              <div>
                <h4 className="text-sm font-semibold text-slate-300 uppercase tracking-wider mb-3">
                  Example Finding
                </h4>
                <div className="bg-slate-900 rounded-lg border border-slate-700 p-4 font-mono text-sm">
                  <span className="text-slate-500"># </span>
                  <span className="text-cyan-400">{activeScanner.example}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Protocol coverage matrix */}
        <div className="mt-16">
          <h3 className="text-xl font-semibold text-white mb-6 text-center">Protocol Coverage Matrix</h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700">
                  <th className="text-left py-3 px-4 text-slate-400 font-medium">Protocol</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">Key Exchange</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">Authentication</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">Encryption</th>
                  <th className="text-center py-3 px-4 text-slate-400 font-medium">PQC Detection</th>
                </tr>
              </thead>
              <tbody>
                {[
                  { protocol: 'TLS 1.3', kex: true, auth: true, enc: true, pqc: true },
                  { protocol: 'TLS 1.2', kex: true, auth: true, enc: true, pqc: true },
                  { protocol: 'SSH', kex: true, auth: true, enc: true, pqc: true },
                  { protocol: 'IKEv2', kex: true, auth: true, enc: true, pqc: true },
                  { protocol: 'STARTTLS', kex: true, auth: true, enc: true, pqc: false },
                  { protocol: 'DNSSEC', kex: false, auth: true, enc: false, pqc: false },
                  { protocol: 'QUIC', kex: true, auth: true, enc: true, pqc: true },
                ].map((row, i) => (
                  <tr key={i} className="border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                    <td className="py-3 px-4 text-white font-medium">{row.protocol}</td>
                    <td className="text-center py-3 px-4">
                      {row.kex ? <span className="text-emerald-400">✓</span> : <span className="text-slate-600">—</span>}
                    </td>
                    <td className="text-center py-3 px-4">
                      {row.auth ? <span className="text-emerald-400">✓</span> : <span className="text-slate-600">—</span>}
                    </td>
                    <td className="text-center py-3 px-4">
                      {row.enc ? <span className="text-emerald-400">✓</span> : <span className="text-slate-600">—</span>}
                    </td>
                    <td className="text-center py-3 px-4">
                      {row.pqc ? <span className="text-emerald-400">✓</span> : <span className="text-yellow-400">○</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </section>
  );
}
