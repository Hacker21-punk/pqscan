import { useState } from 'react';

const features = [
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607zM10.5 7.5v6m3-3h-6" />
      </svg>
    ),
    title: 'Deep Protocol Analysis',
    description: 'Scans TLS 1.0-1.3, SSH, IPSec/IKE, STARTTLS (SMTP, IMAP, POP3, FTP, LDAP, XMPP), QUIC/HTTP3, and DNSSEC. Extracts every cipher suite, key exchange, and certificate in your infrastructure.',
    color: 'cyan',
    details: ['TLS cipher suite enumeration', 'SSH key exchange probing', 'Certificate chain analysis', 'PQC support detection'],
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75m-3-7.036A11.959 11.959 0 013.598 6 11.99 11.99 0 003 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285z" />
      </svg>
    ),
    title: 'CNSA 2.0 Compliance',
    description: "NSA's Commercial National Security Algorithm Suite 2.0 mandates complete PQC migration by 2033-2035. We check every endpoint against every milestone.",
    color: 'blue',
    details: ['2025-2035 timeline tracking', 'ML-KEM/ML-DSA detection', 'SHA-384+ requirement check', 'AES-256 enforcement'],
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75zM9.75 8.625c0-.621.504-1.125 1.125-1.125h2.25c.621 0 1.125.504 1.125 1.125v11.25c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V8.625zM16.5 4.125c0-.621.504-1.125 1.125-1.125h2.25C20.496 3 21 3.504 21 4.125v15.75c0 .621-.504 1.125-1.125 1.125h-2.25a1.125 1.125 0 01-1.125-1.125V4.125z" />
      </svg>
    ),
    title: 'Quantitative Risk Scoring',
    description: 'Get a 0-100 risk score based on algorithm vulnerability, asset criticality, and exposure. Perfect for executive reporting and tracking migration progress.',
    color: 'purple',
    details: ['Weighted scoring model', 'Asset classification', 'Exposure factor calculation', 'HNDL risk assessment'],
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h3.75M9 15h3.75M9 18h3.75m3 .75H18a2.25 2.25 0 002.25-2.25V6.108c0-1.135-.845-2.098-1.976-2.192a48.424 48.424 0 00-1.123-.08m-5.801 0c-.065.21-.1.433-.1.664 0 .414.336.75.75.75h4.5a.75.75 0 00.75-.75 2.25 2.25 0 00-.1-.664m-5.8 0A2.251 2.251 0 0113.5 2.25H15c1.012 0 1.867.668 2.15 1.586m-5.8 0c-.376.023-.75.05-1.124.08C9.095 4.01 8.25 4.973 8.25 6.108V8.25m0 0H4.875c-.621 0-1.125.504-1.125 1.125v11.25c0 .621.504 1.125 1.125 1.125h9.75c.621 0 1.125-.504 1.125-1.125V9.375c0-.621-.504-1.125-1.125-1.125H8.25zM6.75 12h.008v.008H6.75V12zm0 3h.008v.008H6.75V15zm0 3h.008v.008H6.75V18z" />
      </svg>
    ),
    title: 'Cryptographic BOM',
    description: 'Generate a complete inventory of all cryptographic assets in CycloneDX format. Essential for tracking migration and meeting compliance requirements.',
    color: 'green',
    details: ['CycloneDX CBOM export', 'Full asset inventory', 'Dependency tracking', 'SPDX compatible'],
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 21a9.004 9.004 0 008.716-6.747M12 21a9.004 9.004 0 01-8.716-6.747M12 21c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m0 0a8.997 8.997 0 017.843 4.582M12 3a8.997 8.997 0 00-7.843 4.582m15.686 0A11.953 11.953 0 0112 10.5c-2.998 0-5.74-1.1-7.843-2.918m15.686 0A8.959 8.959 0 0121 12c0 .778-.099 1.533-.284 2.253m0 0A17.919 17.919 0 0112 16.5c-3.162 0-6.133-.815-8.716-2.247m0 0A9.015 9.015 0 013 12c0-1.605.42-3.113 1.157-4.418" />
      </svg>
    ),
    title: 'Subdomain Discovery',
    description: 'Automatically discover all subdomains via DNS brute-force, Certificate Transparency logs, and zone transfers. Find shadow IT and forgotten services.',
    color: 'orange',
    details: ['CT log integration', 'DNS brute-force', 'Zone transfer detection', '10,000+ word wordlist'],
  },
  {
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m0 12.75h7.5m-7.5 3H12M10.5 2.25H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
      </svg>
    ),
    title: 'Beautiful Reports',
    description: 'Generate stunning HTML reports that executives actually want to read. Also supports JSON, PDF, SARIF (for CI/CD), and CBOM formats.',
    color: 'pink',
    details: ['Executive summary', 'Interactive HTML', 'SARIF for CI/CD', 'PDF for compliance'],
  },
];

const colorClasses: Record<string, { bg: string; border: string; text: string; iconBg: string }> = {
  cyan: { bg: 'bg-cyan-500/10', border: 'border-cyan-500/30 hover:border-cyan-500/50', text: 'text-cyan-400', iconBg: 'bg-cyan-500/20' },
  blue: { bg: 'bg-blue-500/10', border: 'border-blue-500/30 hover:border-blue-500/50', text: 'text-blue-400', iconBg: 'bg-blue-500/20' },
  purple: { bg: 'bg-purple-500/10', border: 'border-purple-500/30 hover:border-purple-500/50', text: 'text-purple-400', iconBg: 'bg-purple-500/20' },
  green: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30 hover:border-emerald-500/50', text: 'text-emerald-400', iconBg: 'bg-emerald-500/20' },
  orange: { bg: 'bg-orange-500/10', border: 'border-orange-500/30 hover:border-orange-500/50', text: 'text-orange-400', iconBg: 'bg-orange-500/20' },
  pink: { bg: 'bg-pink-500/10', border: 'border-pink-500/30 hover:border-pink-500/50', text: 'text-pink-400', iconBg: 'bg-pink-500/20' },
};

export default function Features() {
  const [expandedIndex, setExpandedIndex] = useState<number | null>(null);

  return (
    <section id="features" className="py-24 bg-slate-950 relative overflow-hidden">
      {/* Background decoration */}
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:6rem_6rem] opacity-30" />
      
      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section header */}
        <div className="text-center mb-16">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm font-medium mb-6">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Powerful Features
          </span>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Everything You Need to
            <br />
            <span className="bg-gradient-to-r from-cyan-400 to-blue-500 bg-clip-text text-transparent">
              Assess Quantum Risk
            </span>
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            A comprehensive toolkit for discovering, classifying, and reporting on 
            quantum-vulnerable cryptography across your entire infrastructure.
          </p>
        </div>

        {/* Features grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature, index) => {
            const colors = colorClasses[feature.color];
            const isExpanded = expandedIndex === index;
            
            return (
              <div
                key={index}
                className={`group relative rounded-2xl ${colors.bg} border ${colors.border} p-6 transition-all duration-300 hover-lift cursor-pointer`}
                onClick={() => setExpandedIndex(isExpanded ? null : index)}
              >
                {/* Icon */}
                <div className={`w-12 h-12 rounded-xl ${colors.iconBg} flex items-center justify-center ${colors.text} mb-4`}>
                  {feature.icon}
                </div>
                
                {/* Title */}
                <h3 className="text-xl font-semibold text-white mb-2 flex items-center gap-2">
                  {feature.title}
                  <svg 
                    className={`w-4 h-4 text-slate-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`} 
                    fill="none" 
                    viewBox="0 0 24 24" 
                    stroke="currentColor" 
                    strokeWidth={2}
                  >
                    <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                  </svg>
                </h3>
                
                {/* Description */}
                <p className="text-slate-400 text-sm leading-relaxed mb-4">
                  {feature.description}
                </p>
                
                {/* Expandable details */}
                <div className={`overflow-hidden transition-all duration-300 ${isExpanded ? 'max-h-40 opacity-100' : 'max-h-0 opacity-0'}`}>
                  <ul className="space-y-2 pt-4 border-t border-slate-700/50">
                    {feature.details.map((detail, i) => (
                      <li key={i} className="flex items-center gap-2 text-sm text-slate-300">
                        <svg className={`w-4 h-4 ${colors.text} flex-shrink-0`} fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                          <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                        </svg>
                        {detail}
                      </li>
                    ))}
                  </ul>
                </div>
              </div>
            );
          })}
        </div>
        
        {/* Bottom CTA */}
        <div className="mt-16 text-center">
          <p className="text-slate-500 mb-4">Ready to find your quantum vulnerabilities?</p>
          <a 
            href="#install"
            className="btn-press inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold hover:from-cyan-400 hover:to-blue-500 transition-all shadow-lg shadow-blue-500/25"
          >
            Get Started Free
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
          </a>
        </div>
      </div>
    </section>
  );
}
