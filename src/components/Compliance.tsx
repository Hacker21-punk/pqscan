import { useState } from 'react';

const timeline = [
  {
    year: '2025',
    title: 'Prefer PQC',
    status: 'now',
    description: 'Software/firmware signing should prefer LMS/XMSS. Key establishment should prefer ML-KEM-1024.',
    requirements: [
      'Begin PQC pilot programs',
      'Prefer ML-KEM for new key establishment',
      'LMS/XMSS for firmware signing',
    ],
  },
  {
    year: '2027',
    title: 'New Equipment',
    status: 'soon',
    description: 'All NEW network equipment must support CNSA 2.0. Web servers and browsers must support ML-KEM.',
    requirements: [
      'New systems must support CNSA 2.0',
      'ML-KEM key exchange required',
      'Hybrid modes acceptable',
    ],
  },
  {
    year: '2029',
    title: 'Exclusive PQC',
    status: 'upcoming',
    description: 'All NEW systems must EXCLUSIVELY use CNSA 2.0 algorithms. No exceptions for new deployments.',
    requirements: [
      'New systems: CNSA 2.0 only',
      'No new RSA/ECDSA deployments',
      'ML-DSA for all new signatures',
    ],
  },
  {
    year: '2030',
    title: 'Legacy Upgrade',
    status: 'upcoming',
    description: 'Legacy symmetric and hashing must be upgraded. All operating systems must support CNSA 2.0.',
    requirements: [
      'AES-256 required (no AES-128)',
      'SHA-384+ required (no SHA-256)',
      'OS-level PQC support mandatory',
    ],
  },
  {
    year: '2033',
    title: 'Full Migration',
    status: 'upcoming',
    description: 'All network protocols (TLS, SSH, IKE, MACsec) must use CNSA 2.0. Complete deprecation of RSA, ECDSA, ECDH.',
    requirements: [
      'Zero tolerance for quantum-vulnerable crypto',
      'All protocols must be PQC-only',
      'Complete RSA/EC deprecation',
    ],
  },
  {
    year: '2035',
    title: 'Complete',
    status: 'future',
    description: 'Full transition complete. No exceptions. All systems must be quantum-safe.',
    requirements: [
      'Mission complete',
      'All infrastructure quantum-safe',
      'Continuous compliance monitoring',
    ],
  },
];

const approvedAlgorithms = [
  { category: 'Key Establishment', algorithms: ['ML-KEM-768', 'ML-KEM-1024'] },
  { category: 'Digital Signatures', algorithms: ['ML-DSA-65', 'ML-DSA-87', 'SLH-DSA (all variants)', 'LMS/HSS', 'XMSS/XMSS-MT'] },
  { category: 'Symmetric Encryption', algorithms: ['AES-256 (GCM, CCM, CBC)'] },
  { category: 'Hashing', algorithms: ['SHA-384', 'SHA-512'] },
];

const prohibitedAlgorithms = [
  { name: 'RSA (any size)', reason: 'Shor\'s algorithm' },
  { name: 'ECDSA/ECDH (any curve)', reason: 'Shor\'s algorithm' },
  { name: 'DH (any size)', reason: 'Shor\'s algorithm' },
  { name: 'DSA', reason: 'Shor\'s algorithm' },
  { name: 'Ed25519/Ed448', reason: 'Shor\'s algorithm' },
  { name: 'AES-128/AES-192', reason: 'Insufficient post-quantum margin' },
  { name: 'SHA-256', reason: 'Not CNSA 2.0 compliant' },
];

export default function Compliance() {
  const [expandedYear, setExpandedYear] = useState<string | null>('2025');
  const currentYear = new Date().getFullYear();

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'now': return 'bg-emerald-500';
      case 'soon': return 'bg-yellow-500';
      case 'upcoming': return 'bg-blue-500';
      default: return 'bg-slate-500';
    }
  };

  return (
    <section id="compliance" className="py-24 bg-slate-900 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-red-500/10 border border-red-500/30 text-red-400 text-sm font-medium mb-6">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
            </svg>
            Compliance Required
          </span>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            <span className="text-red-400">CNSA 2.0</span> Timeline
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            NSA's Commercial National Security Algorithm Suite 2.0 mandates a complete 
            migration to post-quantum cryptography. The clock is ticking.
          </p>
        </div>

        {/* Timeline */}
        <div className="mb-16">
          <div className="relative">
            {/* Timeline line */}
            <div className="absolute left-4 md:left-1/2 top-0 bottom-0 w-0.5 bg-slate-700 md:-translate-x-0.5" />

            {/* Timeline items */}
            <div className="space-y-8">
              {timeline.map((item, index) => {
                const isExpanded = expandedYear === item.year;
                const isPast = parseInt(item.year) <= currentYear;
                
                return (
                  <div 
                    key={item.year}
                    className={`relative flex flex-col md:flex-row gap-4 md:gap-8 ${
                      index % 2 === 0 ? 'md:flex-row-reverse' : ''
                    }`}
                  >
                    {/* Timeline dot */}
                    <div className="absolute left-4 md:left-1/2 w-4 h-4 rounded-full border-4 border-slate-900 md:-translate-x-1/2 z-10">
                      <div className={`w-full h-full rounded-full ${getStatusColor(item.status)} ${item.status === 'now' ? 'animate-pulse' : ''}`} />
                    </div>

                    {/* Content */}
                    <div className={`md:w-1/2 ml-12 md:ml-0 ${index % 2 === 0 ? 'md:pr-12' : 'md:pl-12'}`}>
                      <button
                        onClick={() => setExpandedYear(isExpanded ? null : item.year)}
                        className={`w-full text-left p-6 rounded-xl border transition-all duration-300 ${
                          isExpanded
                            ? 'bg-slate-800/80 border-cyan-500/50'
                            : 'bg-slate-800/40 border-slate-700 hover:bg-slate-800/60 hover:border-slate-600'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-3">
                            <span className={`text-2xl font-bold ${isPast ? 'text-cyan-400' : 'text-white'}`}>
                              {item.year}
                            </span>
                            {item.status === 'now' && (
                              <span className="px-2 py-0.5 rounded text-xs bg-emerald-500/20 text-emerald-400 font-medium">
                                CURRENT
                              </span>
                            )}
                          </div>
                          <svg 
                            className={`w-5 h-5 text-slate-500 transition-transform ${isExpanded ? 'rotate-180' : ''}`}
                            fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}
                          >
                            <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
                          </svg>
                        </div>
                        
                        <h3 className="text-lg font-semibold text-white mb-2">{item.title}</h3>
                        <p className="text-slate-400 text-sm">{item.description}</p>

                        {isExpanded && (
                          <div className="mt-4 pt-4 border-t border-slate-700">
                            <h4 className="text-sm font-semibold text-slate-300 mb-2">Requirements:</h4>
                            <ul className="space-y-1">
                              {item.requirements.map((req, i) => (
                                <li key={i} className="flex items-start gap-2 text-sm text-slate-400">
                                  <svg className="w-4 h-4 text-cyan-400 mt-0.5 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                                    <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
                                  </svg>
                                  {req}
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Approved vs Prohibited */}
        <div className="grid md:grid-cols-2 gap-8 mb-16">
          {/* Approved */}
          <div className="bg-emerald-500/5 rounded-2xl border border-emerald-500/30 p-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-lg bg-emerald-500/20 flex items-center justify-center">
                <svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-white">CNSA 2.0 Approved</h3>
            </div>
            
            <div className="space-y-4">
              {approvedAlgorithms.map((group, i) => (
                <div key={i}>
                  <h4 className="text-sm font-semibold text-slate-400 mb-2">{group.category}</h4>
                  <div className="flex flex-wrap gap-2">
                    {group.algorithms.map((algo, j) => (
                      <span key={j} className="px-3 py-1 rounded-lg bg-emerald-500/20 text-emerald-400 text-sm font-mono">
                        {algo}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Prohibited */}
          <div className="bg-red-500/5 rounded-2xl border border-red-500/30 p-8">
            <div className="flex items-center gap-3 mb-6">
              <div className="w-10 h-10 rounded-lg bg-red-500/20 flex items-center justify-center">
                <svg className="w-5 h-5 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                  <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
                </svg>
              </div>
              <h3 className="text-xl font-semibold text-white">CNSA 2.0 Prohibited</h3>
            </div>
            
            <div className="space-y-2">
              {prohibitedAlgorithms.map((algo, i) => (
                <div key={i} className="flex items-center justify-between py-2 border-b border-slate-800 last:border-0">
                  <span className="font-mono text-red-400 text-sm">{algo.name}</span>
                  <span className="text-slate-500 text-xs">{algo.reason}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* HNDL Warning */}
        <div className="bg-gradient-to-r from-red-500/10 via-orange-500/10 to-red-500/10 rounded-2xl border border-red-500/30 p-8">
          <div className="flex items-start gap-4">
            <div className="flex-shrink-0 w-12 h-12 rounded-xl bg-red-500/20 flex items-center justify-center">
              <svg className="w-6 h-6 text-red-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
              </svg>
            </div>
            <div>
              <h3 className="text-xl font-bold text-white mb-2">
                ⚠️ Harvest Now, Decrypt Later (HNDL)
              </h3>
              <p className="text-slate-300 mb-4">
                Adversaries are <span className="text-red-400 font-semibold">already capturing encrypted traffic</span> today, 
                waiting for quantum computers to decrypt it later. If your data needs to remain 
                confidential for more than 10 years, <span className="text-red-400 font-semibold">it's already at risk</span>.
              </p>
              <div className="flex flex-wrap gap-4 text-sm">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-slate-400">Government secrets</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-slate-400">Healthcare records</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-slate-400">Financial data</span>
                </div>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-red-500" />
                  <span className="text-slate-400">Trade secrets</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
