const modules = [
  {
    name: 'cmd/pqscan',
    description: 'CLI entrypoint with Cobra framework',
    files: ['main.go'],
    color: 'cyan',
  },
  {
    name: 'scanner/',
    description: 'Protocol-specific scanners',
    files: ['scanner.go', 'tls_scanner.go', 'ssh_scanner.go', 'ipsec_scanner.go', 'starttls_scanner.go', 'cert_scanner.go', 'dns_scanner.go', 'quic_scanner.go'],
    color: 'blue',
  },
  {
    name: 'discovery/',
    description: 'Target discovery & enumeration',
    files: ['discovery.go', 'subdomain.go', 'port_scan.go', 'service_detect.go'],
    color: 'purple',
  },
  {
    name: 'classifier/',
    description: 'Risk classification engine',
    files: ['classifier.go', 'algorithms.go', 'risk_score.go', 'cnsa_compliance.go'],
    color: 'orange',
  },
  {
    name: 'reporter/',
    description: 'Report generation',
    files: ['reporter.go', 'cli_report.go', 'html_report.go', 'json_report.go', 'pdf_report.go', 'sarif_report.go'],
    color: 'pink',
  },
  {
    name: 'cbom/',
    description: 'Cryptographic Bill of Materials',
    files: ['cbom.go', 'inventory.go', 'export.go'],
    color: 'green',
  },
  {
    name: 'crypto/',
    description: 'Algorithm database & analysis',
    files: ['cipher_suites.go', 'key_analysis.go', 'pqc_algorithms.go', 'chinese_standards.go'],
    color: 'yellow',
  },
];

const techStack = [
  { name: 'Go 1.21+', description: 'Pure Go, CGO-free' },
  { name: 'Cobra', description: 'CLI framework' },
  { name: 'Viper', description: 'Configuration' },
  { name: 'zerolog', description: 'Structured logging' },
  { name: 'golang.org/x/crypto', description: 'SSH protocol support' },
  { name: 'miekg/dns', description: 'DNS queries' },
  { name: 'CycloneDX', description: 'CBOM format' },
];

export default function Architecture() {
  return (
    <section id="architecture" className="py-24 bg-slate-900 relative overflow-hidden">
      <div className="absolute inset-0 bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-purple-500/10 border border-purple-500/30 text-purple-400 text-sm font-medium mb-6">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
            </svg>
            Clean Architecture
          </span>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Built for <span className="text-purple-400">Extensibility</span>
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Modular design with clear separation of concerns. Each component can be 
            extended or replaced without affecting others.
          </p>
        </div>

        {/* Flow diagram */}
        <div className="mb-16">
          <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-8 overflow-x-auto">
            <div className="flex items-center justify-between min-w-[800px] gap-4">
              {[
                { icon: '🎯', name: 'Target', desc: 'Input' },
                { icon: '🔍', name: 'Discover', desc: 'Enumerate' },
                { icon: '📡', name: 'Scan', desc: 'Connect' },
                { icon: '⚖️', name: 'Classify', desc: 'Score' },
                { icon: '📊', name: 'Report', desc: 'Output' },
              ].map((step, i, arr) => (
                <div key={i} className="flex items-center gap-4 flex-1">
                  <div className="flex flex-col items-center text-center flex-1">
                    <div className="w-16 h-16 rounded-2xl bg-slate-700 flex items-center justify-center text-2xl mb-2">
                      {step.icon}
                    </div>
                    <div className="font-semibold text-white">{step.name}</div>
                    <div className="text-xs text-slate-500">{step.desc}</div>
                  </div>
                  {i < arr.length - 1 && (
                    <svg className="w-8 h-8 text-slate-600 flex-shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                    </svg>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Modules grid */}
        <div className="grid md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 mb-16">
          {modules.map((module, i) => (
            <div
              key={i}
              className="bg-slate-800/50 rounded-xl border border-slate-700 p-4 hover:border-slate-600 transition-colors"
            >
              <div className="flex items-center gap-2 mb-2">
                <span className={`w-2 h-2 rounded-full bg-${module.color}-400`} />
                <h4 className="font-mono font-semibold text-white text-sm">{module.name}</h4>
              </div>
              <p className="text-xs text-slate-500 mb-3">{module.description}</p>
              <div className="flex flex-wrap gap-1">
                {module.files.slice(0, 4).map((file, j) => (
                  <span key={j} className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-400 text-[10px] font-mono">
                    {file}
                  </span>
                ))}
                {module.files.length > 4 && (
                  <span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-500 text-[10px]">
                    +{module.files.length - 4} more
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Tech stack & Build targets */}
        <div className="grid md:grid-cols-2 gap-8">
          {/* Tech Stack */}
          <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <svg className="w-5 h-5 text-cyan-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
              </svg>
              Tech Stack
            </h3>
            <div className="space-y-3">
              {techStack.map((tech, i) => (
                <div key={i} className="flex items-center justify-between py-2 border-b border-slate-700 last:border-0">
                  <span className="font-mono text-cyan-400 text-sm">{tech.name}</span>
                  <span className="text-slate-500 text-xs">{tech.description}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Build Targets */}
          <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-6">
            <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
              <svg className="w-5 h-5 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M8 9l3 3-3 3m5 0h3M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
              </svg>
              Build Targets
            </h3>
            <div className="grid grid-cols-2 gap-2">
              {[
                { os: 'Linux', arch: 'amd64 / arm64' },
                { os: 'macOS', arch: 'amd64 / arm64' },
                { os: 'Windows', arch: 'amd64 / arm64' },
                { os: 'FreeBSD', arch: 'amd64' },
              ].map((target, i) => (
                <div key={i} className="bg-slate-900 rounded-lg p-3 text-center">
                  <div className="font-semibold text-white text-sm">{target.os}</div>
                  <div className="text-xs text-slate-500">{target.arch}</div>
                </div>
              ))}
            </div>
            
            <div className="mt-4 pt-4 border-t border-slate-700">
              <h4 className="text-sm font-semibold text-slate-300 mb-2">Quality Standards</h4>
              <div className="flex flex-wrap gap-2">
                {['CGO_ENABLED=0', 'Race detection', '90%+ coverage', 'golangci-lint', 'Fuzz testing'].map((item, i) => (
                  <span key={i} className="px-2 py-1 rounded bg-emerald-500/10 text-emerald-400 text-xs">
                    {item}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* GitHub CTA */}
        <div className="mt-12 text-center">
          <a
            href="https://github.com/pqscan/pqscan"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-press inline-flex items-center gap-3 px-8 py-4 rounded-xl bg-slate-800 border border-slate-700 text-white font-semibold hover:bg-slate-700 hover:border-slate-600 transition-all"
          >
            <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
              <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
            </svg>
            View Source on GitHub
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M10 6H6a2 2 0 00-2 2v10a2 2 0 002 2h10a2 2 0 002-2v-4M14 4h6m0 0v6m0-6L10 14" />
            </svg>
          </a>
        </div>
      </div>
    </section>
  );
}
