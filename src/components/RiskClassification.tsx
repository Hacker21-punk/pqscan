import { useState } from 'react';

const riskLevels = [
  {
    level: 'CRITICAL',
    color: 'red',
    icon: '🔴',
    description: 'Algorithm is completely broken by Shor\'s algorithm. Key recovery or signature forgery is possible.',
    quantumThreat: 'Shor\'s Algorithm',
    examples: ['RSA-2048', 'ECDHE-P256', 'ECDSA-P384', 'DH-2048', 'Ed25519'],
    impact: 'Total compromise',
    timeline: 'Migrate immediately',
  },
  {
    level: 'HIGH',
    color: 'orange',
    icon: '🟠',
    description: 'Algorithm severely weakened by quantum attacks. Effective security drops below acceptable thresholds.',
    quantumThreat: 'Grover\'s (2x speedup)',
    examples: ['AES-128 (→64-bit)', 'SHA-1', '3DES'],
    impact: 'Effectively broken',
    timeline: 'Migrate within 1 year',
  },
  {
    level: 'MODERATE',
    color: 'yellow',
    icon: '🟡',
    description: 'Algorithm is weakened but retains adequate security. Should be upgraded but is not an emergency.',
    quantumThreat: 'Grover\'s (2x speedup)',
    examples: ['AES-192 (→96-bit)', 'SHA-256 (→128-bit collision)'],
    impact: 'Weakened security',
    timeline: 'Plan migration',
  },
  {
    level: 'LOW',
    color: 'blue',
    icon: '🔵',
    description: 'Algorithm minimally impacted by quantum attacks. Still meets post-quantum security requirements.',
    quantumThreat: 'Grover\'s (minimal)',
    examples: ['AES-256 (→128-bit)', 'SHA-384', 'SHA-512', 'SHAKE256'],
    impact: 'Acceptable',
    timeline: 'Monitor standards',
  },
  {
    level: 'SAFE',
    color: 'green',
    icon: '🟢',
    description: 'Algorithm is quantum-safe by design. No known quantum attacks provide meaningful advantage.',
    quantumThreat: 'None',
    examples: ['ML-KEM-768', 'ML-DSA-65', 'SLH-DSA', 'FN-DSA-512', 'XMSS'],
    impact: 'None',
    timeline: 'You\'re prepared!',
  },
];

const colorClasses: Record<string, { bg: string; border: string; text: string; badge: string }> = {
  red: { bg: 'bg-red-500/10', border: 'border-red-500/50', text: 'text-red-400', badge: 'bg-red-500' },
  orange: { bg: 'bg-orange-500/10', border: 'border-orange-500/50', text: 'text-orange-400', badge: 'bg-orange-500' },
  yellow: { bg: 'bg-yellow-500/10', border: 'border-yellow-500/50', text: 'text-yellow-400', badge: 'bg-yellow-500' },
  blue: { bg: 'bg-blue-500/10', border: 'border-blue-500/50', text: 'text-blue-400', badge: 'bg-blue-500' },
  green: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/50', text: 'text-emerald-400', badge: 'bg-emerald-500' },
};

export default function RiskClassification() {
  const [selectedLevel, setSelectedLevel] = useState(riskLevels[0]);

  return (
    <section id="risk-scoring" className="py-24 bg-slate-900 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section header */}
        <div className="text-center mb-16">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-orange-500/10 border border-orange-500/30 text-orange-400 text-sm font-medium mb-6">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M3 13.125C3 12.504 3.504 12 4.125 12h2.25c.621 0 1.125.504 1.125 1.125v6.75C7.5 20.496 6.996 21 6.375 21h-2.25A1.125 1.125 0 013 19.875v-6.75z" />
            </svg>
            Risk Classification
          </span>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Quantitative <span className="text-orange-400">Risk Scoring</span>
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Every algorithm is classified based on its vulnerability to quantum attacks.
            Your overall score reflects the weakest link in your cryptographic chain.
          </p>
        </div>

        {/* Risk level selector */}
        <div className="flex flex-wrap justify-center gap-2 mb-12">
          {riskLevels.map((level) => {
            const colors = colorClasses[level.color];
            const isSelected = selectedLevel.level === level.level;
            
            return (
              <button
                key={level.level}
                onClick={() => setSelectedLevel(level)}
                className={`px-4 py-2 rounded-lg font-semibold text-sm transition-all ${
                  isSelected
                    ? `${colors.bg} ${colors.border} border-2 ${colors.text}`
                    : 'bg-slate-800 border-2 border-transparent text-slate-400 hover:text-white hover:bg-slate-700'
                }`}
              >
                <span className="mr-2">{level.icon}</span>
                {level.level}
              </button>
            );
          })}
        </div>

        {/* Selected level detail */}
        <div className="grid lg:grid-cols-2 gap-8 mb-16">
          <div className={`rounded-2xl ${colorClasses[selectedLevel.color].bg} border ${colorClasses[selectedLevel.color].border} p-8`}>
            <div className="flex items-center gap-4 mb-6">
              <span className="text-5xl">{selectedLevel.icon}</span>
              <div>
                <h3 className={`text-3xl font-bold ${colorClasses[selectedLevel.color].text}`}>
                  {selectedLevel.level}
                </h3>
                <div className="text-slate-500">{selectedLevel.quantumThreat}</div>
              </div>
            </div>
            
            <p className="text-slate-300 mb-6">
              {selectedLevel.description}
            </p>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <div className="text-sm text-slate-500 mb-1">Impact</div>
                <div className={`font-semibold ${colorClasses[selectedLevel.color].text}`}>
                  {selectedLevel.impact}
                </div>
              </div>
              <div>
                <div className="text-sm text-slate-500 mb-1">Action</div>
                <div className="text-white font-semibold">{selectedLevel.timeline}</div>
              </div>
            </div>
          </div>

          <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-8">
            <h4 className="text-lg font-semibold text-white mb-4">Example Algorithms</h4>
            <div className="flex flex-wrap gap-2">
              {selectedLevel.examples.map((example, i) => (
                <span
                  key={i}
                  className={`px-3 py-1.5 rounded-lg ${colorClasses[selectedLevel.color].bg} ${colorClasses[selectedLevel.color].text} text-sm font-mono`}
                >
                  {example}
                </span>
              ))}
            </div>
          </div>
        </div>

        {/* Scoring formula */}
        <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-8">
          <h3 className="text-xl font-semibold text-white mb-6 text-center">
            How Scores Are Calculated
          </h3>
          
          <div className="grid md:grid-cols-3 gap-8">
            {/* Formula */}
            <div className="md:col-span-2">
              <div className="bg-slate-900 rounded-xl p-6 font-mono text-sm mb-6">
                <div className="text-slate-500 mb-2">// Organizational Risk Score</div>
                <div className="text-cyan-400">
                  score = Σ (asset_risk × asset_weight × exposure) / max_score × 100
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <h5 className="text-sm font-semibold text-slate-300 mb-2">Asset Weights</h5>
                  <ul className="space-y-1 text-sm text-slate-400">
                    <li>• Certificate Authority: <span className="text-white">2.0×</span></li>
                    <li>• Database: <span className="text-white">1.8×</span></li>
                    <li>• VPN Gateway: <span className="text-white">1.5×</span></li>
                    <li>• SSH Bastion: <span className="text-white">1.3×</span></li>
                    <li>• Email Server: <span className="text-white">1.2×</span></li>
                    <li>• Web Server: <span className="text-white">1.0×</span></li>
                  </ul>
                </div>
                <div>
                  <h5 className="text-sm font-semibold text-slate-300 mb-2">Exposure Factors</h5>
                  <ul className="space-y-1 text-sm text-slate-400">
                    <li>• Internet-facing: <span className="text-white">1.0×</span></li>
                    <li>• DMZ: <span className="text-white">0.7×</span></li>
                    <li>• Internal: <span className="text-white">0.3×</span></li>
                    <li>• Air-gapped: <span className="text-white">0.1×</span></li>
                  </ul>
                </div>
              </div>
            </div>

            {/* Example calculation */}
            <div className="bg-slate-900 rounded-xl p-6">
              <h5 className="text-sm font-semibold text-slate-300 mb-4">Example</h5>
              <div className="space-y-3 text-sm">
                <div className="flex justify-between text-slate-400">
                  <span>TLS Endpoint (ECDHE-P256)</span>
                  <span className="text-red-400">CRITICAL</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>• Risk Level:</span>
                  <span className="text-white">10 pts</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>• Web Server Weight:</span>
                  <span className="text-white">× 1.0</span>
                </div>
                <div className="flex justify-between text-slate-400">
                  <span>• Internet-facing:</span>
                  <span className="text-white">× 1.0</span>
                </div>
                <div className="border-t border-slate-700 pt-3 flex justify-between">
                  <span className="text-slate-300">Contribution:</span>
                  <span className="text-white font-semibold">10 / 10 = 100%</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}
