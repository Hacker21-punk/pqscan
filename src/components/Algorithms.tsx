import { useState, useMemo } from 'react';

type AlgorithmCategory = 'key-exchange' | 'signatures' | 'symmetric' | 'hash';

interface Algorithm {
  name: string;
  category: AlgorithmCategory;
  classicalBits: number;
  quantumBits: number | string;
  threat: 'Shor' | 'Grover' | 'None';
  risk: 'CRITICAL' | 'HIGH' | 'MODERATE' | 'LOW' | 'SAFE';
  cnsa: 'Approved' | 'Deprecated' | 'Prohibited';
  migration?: string;
}

const algorithms: Algorithm[] = [
  // Key Exchange
  { name: 'RSA-2048', category: 'key-exchange', classicalBits: 112, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-KEM-768' },
  { name: 'RSA-4096', category: 'key-exchange', classicalBits: 140, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-KEM-1024' },
  { name: 'DH-2048', category: 'key-exchange', classicalBits: 112, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-KEM-768' },
  { name: 'ECDH-P256', category: 'key-exchange', classicalBits: 128, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-KEM-768' },
  { name: 'ECDH-P384', category: 'key-exchange', classicalBits: 192, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-KEM-1024' },
  { name: 'X25519', category: 'key-exchange', classicalBits: 128, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-KEM-768' },
  { name: 'X448', category: 'key-exchange', classicalBits: 224, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-KEM-1024' },
  { name: 'ML-KEM-512', category: 'key-exchange', classicalBits: 128, quantumBits: 128, threat: 'None', risk: 'SAFE', cnsa: 'Deprecated' },
  { name: 'ML-KEM-768', category: 'key-exchange', classicalBits: 192, quantumBits: 192, threat: 'None', risk: 'SAFE', cnsa: 'Approved' },
  { name: 'ML-KEM-1024', category: 'key-exchange', classicalBits: 256, quantumBits: 256, threat: 'None', risk: 'SAFE', cnsa: 'Approved' },
  { name: 'X25519Kyber768', category: 'key-exchange', classicalBits: 192, quantumBits: 192, threat: 'None', risk: 'SAFE', cnsa: 'Approved' },
  { name: 'SIKE/SIDH', category: 'key-exchange', classicalBits: 0, quantumBits: 0, threat: 'None', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'BROKEN - Classical attack found 2022' },
  
  // Signatures
  { name: 'RSA-PKCS#1 v1.5', category: 'signatures', classicalBits: 112, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-DSA-65' },
  { name: 'RSA-PSS', category: 'signatures', classicalBits: 112, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-DSA-65' },
  { name: 'ECDSA-P256', category: 'signatures', classicalBits: 128, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-DSA-65' },
  { name: 'ECDSA-P384', category: 'signatures', classicalBits: 192, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-DSA-87' },
  { name: 'Ed25519', category: 'signatures', classicalBits: 128, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-DSA-65' },
  { name: 'Ed448', category: 'signatures', classicalBits: 224, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-DSA-87' },
  { name: 'DSA-2048', category: 'signatures', classicalBits: 112, quantumBits: 0, threat: 'Shor', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'ML-DSA-65' },
  { name: 'ML-DSA-44', category: 'signatures', classicalBits: 128, quantumBits: 128, threat: 'None', risk: 'SAFE', cnsa: 'Deprecated' },
  { name: 'ML-DSA-65', category: 'signatures', classicalBits: 192, quantumBits: 192, threat: 'None', risk: 'SAFE', cnsa: 'Approved' },
  { name: 'ML-DSA-87', category: 'signatures', classicalBits: 256, quantumBits: 256, threat: 'None', risk: 'SAFE', cnsa: 'Approved' },
  { name: 'SLH-DSA-SHA2-128s', category: 'signatures', classicalBits: 128, quantumBits: 128, threat: 'None', risk: 'SAFE', cnsa: 'Approved' },
  { name: 'FN-DSA-512', category: 'signatures', classicalBits: 128, quantumBits: 128, threat: 'None', risk: 'SAFE', cnsa: 'Approved' },
  { name: 'LMS/HSS', category: 'signatures', classicalBits: 256, quantumBits: 256, threat: 'None', risk: 'SAFE', cnsa: 'Approved' },
  
  // Symmetric
  { name: 'AES-128', category: 'symmetric', classicalBits: 128, quantumBits: 64, threat: 'Grover', risk: 'HIGH', cnsa: 'Prohibited', migration: 'AES-256' },
  { name: 'AES-192', category: 'symmetric', classicalBits: 192, quantumBits: 96, threat: 'Grover', risk: 'MODERATE', cnsa: 'Prohibited', migration: 'AES-256' },
  { name: 'AES-256', category: 'symmetric', classicalBits: 256, quantumBits: 128, threat: 'Grover', risk: 'LOW', cnsa: 'Approved' },
  { name: 'ChaCha20', category: 'symmetric', classicalBits: 256, quantumBits: 128, threat: 'Grover', risk: 'LOW', cnsa: 'Deprecated' },
  { name: '3DES', category: 'symmetric', classicalBits: 112, quantumBits: 56, threat: 'Grover', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'AES-256' },
  { name: 'DES', category: 'symmetric', classicalBits: 56, quantumBits: 28, threat: 'Grover', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'AES-256' },
  { name: 'RC4', category: 'symmetric', classicalBits: 0, quantumBits: 0, threat: 'None', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'BROKEN classically' },
  { name: 'SM4', category: 'symmetric', classicalBits: 128, quantumBits: 64, threat: 'Grover', risk: 'HIGH', cnsa: 'Prohibited' },
  
  // Hash
  { name: 'MD5', category: 'hash', classicalBits: 0, quantumBits: 0, threat: 'None', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'SHA-384' },
  { name: 'SHA-1', category: 'hash', classicalBits: 0, quantumBits: 0, threat: 'None', risk: 'CRITICAL', cnsa: 'Prohibited', migration: 'SHA-384' },
  { name: 'SHA-256', category: 'hash', classicalBits: 256, quantumBits: 128, threat: 'Grover', risk: 'MODERATE', cnsa: 'Prohibited', migration: 'SHA-384' },
  { name: 'SHA-384', category: 'hash', classicalBits: 384, quantumBits: 192, threat: 'Grover', risk: 'LOW', cnsa: 'Approved' },
  { name: 'SHA-512', category: 'hash', classicalBits: 512, quantumBits: 256, threat: 'Grover', risk: 'LOW', cnsa: 'Approved' },
  { name: 'SHA3-256', category: 'hash', classicalBits: 256, quantumBits: 128, threat: 'Grover', risk: 'MODERATE', cnsa: 'Deprecated' },
  { name: 'SHAKE256', category: 'hash', classicalBits: 256, quantumBits: 256, threat: 'Grover', risk: 'LOW', cnsa: 'Approved' },
  { name: 'BLAKE3', category: 'hash', classicalBits: 256, quantumBits: 128, threat: 'Grover', risk: 'LOW', cnsa: 'Deprecated' },
];

const categories = [
  { id: 'key-exchange', name: 'Key Exchange', icon: '🔑' },
  { id: 'signatures', name: 'Signatures', icon: '✍️' },
  { id: 'symmetric', name: 'Symmetric', icon: '🔒' },
  { id: 'hash', name: 'Hash', icon: '#️⃣' },
];

const riskColors: Record<string, { bg: string; text: string }> = {
  CRITICAL: { bg: 'bg-red-500/20', text: 'text-red-400' },
  HIGH: { bg: 'bg-orange-500/20', text: 'text-orange-400' },
  MODERATE: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  LOW: { bg: 'bg-blue-500/20', text: 'text-blue-400' },
  SAFE: { bg: 'bg-emerald-500/20', text: 'text-emerald-400' },
};

const cnsaColors: Record<string, { bg: string; text: string }> = {
  Approved: { bg: 'bg-emerald-500/20', text: 'text-emerald-400' },
  Deprecated: { bg: 'bg-yellow-500/20', text: 'text-yellow-400' },
  Prohibited: { bg: 'bg-red-500/20', text: 'text-red-400' },
};

export default function Algorithms() {
  const [activeCategory, setActiveCategory] = useState<AlgorithmCategory>('key-exchange');
  const [searchQuery, setSearchQuery] = useState('');
  const [riskFilter, setRiskFilter] = useState<string | null>(null);

  const filteredAlgorithms = useMemo(() => {
    return algorithms.filter(algo => {
      if (algo.category !== activeCategory) return false;
      if (searchQuery && !algo.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
      if (riskFilter && algo.risk !== riskFilter) return false;
      return true;
    });
  }, [activeCategory, searchQuery, riskFilter]);

  return (
    <section id="algorithms" className="py-24 bg-slate-950 relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-30" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-12">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-cyan-500/10 border border-cyan-500/30 text-cyan-400 text-sm font-medium mb-6">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4" />
            </svg>
            Algorithm Database
          </span>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            100+ <span className="text-cyan-400">Algorithms</span> Classified
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Every cryptographic algorithm used in production, classified by quantum vulnerability,
            effective security bits, and CNSA 2.0 compliance status.
          </p>
        </div>

        {/* Category tabs */}
        <div className="flex flex-wrap justify-center gap-2 mb-8">
          {categories.map((cat) => (
            <button
              key={cat.id}
              onClick={() => setActiveCategory(cat.id as AlgorithmCategory)}
              className={`px-4 py-2 rounded-lg font-medium text-sm transition-all flex items-center gap-2 ${
                activeCategory === cat.id
                  ? 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-400'
                  : 'bg-slate-800 border border-slate-700 text-slate-400 hover:text-white'
              }`}
            >
              <span>{cat.icon}</span>
              {cat.name}
            </button>
          ))}
        </div>

        {/* Filters */}
        <div className="flex flex-wrap items-center justify-between gap-4 mb-6">
          <div className="flex-1 min-w-[200px] max-w-md">
            <div className="relative">
              <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
              </svg>
              <input
                type="text"
                placeholder="Search algorithms..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full pl-10 pr-4 py-2 rounded-lg bg-slate-800 border border-slate-700 text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
            </div>
          </div>
          
          <div className="flex gap-2">
            {['CRITICAL', 'HIGH', 'MODERATE', 'LOW', 'SAFE'].map((risk) => (
              <button
                key={risk}
                onClick={() => setRiskFilter(riskFilter === risk ? null : risk)}
                className={`px-3 py-1 rounded text-xs font-medium transition-all ${
                  riskFilter === risk
                    ? `${riskColors[risk].bg} ${riskColors[risk].text} ring-1 ring-current`
                    : 'bg-slate-800 text-slate-500 hover:text-slate-300'
                }`}
              >
                {risk}
              </button>
            ))}
          </div>
        </div>

        {/* Algorithm table */}
        <div className="bg-slate-800/50 rounded-2xl border border-slate-700 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-700 bg-slate-900/50">
                  <th className="text-left py-4 px-4 text-slate-400 font-medium">Algorithm</th>
                  <th className="text-center py-4 px-4 text-slate-400 font-medium">Classical</th>
                  <th className="text-center py-4 px-4 text-slate-400 font-medium">Quantum</th>
                  <th className="text-center py-4 px-4 text-slate-400 font-medium">Threat</th>
                  <th className="text-center py-4 px-4 text-slate-400 font-medium">Risk</th>
                  <th className="text-center py-4 px-4 text-slate-400 font-medium">CNSA 2.0</th>
                  <th className="text-left py-4 px-4 text-slate-400 font-medium">Migration</th>
                </tr>
              </thead>
              <tbody>
                {filteredAlgorithms.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center text-slate-500">
                      No algorithms found matching your criteria
                    </td>
                  </tr>
                ) : (
                  filteredAlgorithms.map((algo, i) => (
                    <tr key={i} className="border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                      <td className="py-3 px-4">
                        <span className="font-mono text-white">{algo.name}</span>
                      </td>
                      <td className="text-center py-3 px-4">
                        <span className={`font-mono ${algo.classicalBits === 0 ? 'text-red-400' : 'text-slate-300'}`}>
                          {algo.classicalBits === 0 ? 'BROKEN' : `${algo.classicalBits}-bit`}
                        </span>
                      </td>
                      <td className="text-center py-3 px-4">
                        <span className={`font-mono ${algo.quantumBits === 0 ? 'text-red-400' : 'text-slate-300'}`}>
                          {algo.quantumBits === 0 ? 'BROKEN' : `${algo.quantumBits}-bit`}
                        </span>
                      </td>
                      <td className="text-center py-3 px-4">
                        <span className={`text-xs font-medium ${
                          algo.threat === 'Shor' ? 'text-red-400' :
                          algo.threat === 'Grover' ? 'text-yellow-400' : 'text-emerald-400'
                        }`}>
                          {algo.threat}
                        </span>
                      </td>
                      <td className="text-center py-3 px-4">
                        <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${riskColors[algo.risk].bg} ${riskColors[algo.risk].text}`}>
                          {algo.risk}
                        </span>
                      </td>
                      <td className="text-center py-3 px-4">
                        <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium ${cnsaColors[algo.cnsa].bg} ${cnsaColors[algo.cnsa].text}`}>
                          {algo.cnsa}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-slate-500 text-xs">
                          {algo.migration || '—'}
                        </span>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Legend */}
        <div className="mt-8 flex flex-wrap justify-center gap-6 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-red-400 font-semibold">Shor's</span>
            <span className="text-slate-500">= Complete break</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-yellow-400 font-semibold">Grover's</span>
            <span className="text-slate-500">= √N speedup (halves security)</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-emerald-400 font-semibold">None</span>
            <span className="text-slate-500">= Quantum-safe</span>
          </div>
        </div>
      </div>
    </section>
  );
}
