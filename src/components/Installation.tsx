import { useState } from 'react';

type InstallMethod = 'binary' | 'go' | 'docker' | 'homebrew';

const installMethods = [
  {
    id: 'binary' as InstallMethod,
    name: 'Binary',
    icon: '📦',
    command: 'curl -sSfL https://pqscan.io/install.sh | sh',
    description: 'Fastest way to install. Downloads pre-built binary for your platform.',
  },
  {
    id: 'go' as InstallMethod,
    name: 'Go Install',
    icon: '🐹',
    command: 'go install github.com/pqscan/pqscan/cmd/pqscan@latest',
    description: 'Install via Go toolchain. Requires Go 1.21+.',
  },
  {
    id: 'docker' as InstallMethod,
    name: 'Docker',
    icon: '🐳',
    command: 'docker pull ghcr.io/pqscan/pqscan:latest',
    description: 'Run in container. Perfect for CI/CD pipelines.',
  },
  {
    id: 'homebrew' as InstallMethod,
    name: 'Homebrew',
    icon: '🍺',
    command: 'brew install pqscan/tap/pqscan',
    description: 'Install via Homebrew on macOS/Linux.',
  },
];

const usageExamples = [
  {
    title: 'Quick Scan',
    command: 'pqscan example.com',
    description: 'Scan a single domain with default settings.',
  },
  {
    title: 'Deep Scan',
    command: 'pqscan --profile deep example.com',
    description: 'Full scan with subdomain enumeration.',
  },
  {
    title: 'HTML Report',
    command: 'pqscan --format html --output report.html example.com',
    description: 'Generate beautiful HTML report.',
  },
  {
    title: 'CNSA Compliance',
    command: 'pqscan --profile compliance example.com',
    description: 'Check CNSA 2.0 compliance status.',
  },
  {
    title: 'CI/CD Mode',
    command: 'pqscan --ci --threshold 50 example.com',
    description: 'Fail build if risk score exceeds threshold.',
  },
  {
    title: 'CBOM Export',
    command: 'pqscan --format cbom --output cbom.json example.com',
    description: 'Generate Cryptographic Bill of Materials.',
  },
  {
    title: 'Multiple Targets',
    command: 'pqscan --targets servers.txt',
    description: 'Scan targets from a file.',
  },
  {
    title: 'Docker Scan',
    command: 'docker run ghcr.io/pqscan/pqscan example.com',
    description: 'Run scan in Docker container.',
  },
];

const cliFlags = [
  { flag: '-p, --profile', values: 'quick, standard, deep, compliance', description: 'Scan profile preset' },
  { flag: '-f, --format', values: 'cli, json, html, pdf, sarif, cbom', description: 'Output format' },
  { flag: '-o, --output', values: '<file>', description: 'Output file path' },
  { flag: '-w, --workers', values: '<number>', description: 'Concurrent scan workers (default: 20)' },
  { flag: '-t, --timeout', values: '<duration>', description: 'Per-endpoint timeout (default: 10s)' },
  { flag: '--ports', values: '<list>', description: 'Custom ports to scan' },
  { flag: '--enumerate', values: '', description: 'Enable subdomain enumeration' },
  { flag: '--ci', values: '', description: 'CI/CD mode with exit codes' },
  { flag: '--threshold', values: '<0-100>', description: 'Risk score threshold for CI' },
  { flag: '-q, --quiet', values: '', description: 'Only output the risk score' },
  { flag: '-v, --verbose', values: '', description: 'Show detailed findings' },
  { flag: '--no-color', values: '', description: 'Disable colored output' },
];

export default function Installation() {
  const [activeMethod, setActiveMethod] = useState<InstallMethod>('binary');
  const [copiedCommand, setCopiedCommand] = useState<string | null>(null);

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedCommand(text);
    setTimeout(() => setCopiedCommand(null), 2000);
  };

  const currentMethod = installMethods.find(m => m.id === activeMethod)!;

  return (
    <section id="install" className="py-24 bg-slate-950 relative overflow-hidden">
      <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] opacity-30" />
      
      {/* Gradient accents */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/10 rounded-full blur-3xl" />
      <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/10 rounded-full blur-3xl" />

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="text-center mb-16">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-emerald-500/10 border border-emerald-500/30 text-emerald-400 text-sm font-medium mb-6">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
            </svg>
            Get Started in Seconds
          </span>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            Install <span className="text-cyan-400">pqscan</span>
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Choose your preferred installation method. Works on Linux, macOS, and Windows.
          </p>
        </div>

        {/* Install method tabs */}
        <div className="flex flex-wrap justify-center gap-2 mb-8">
          {installMethods.map((method) => (
            <button
              key={method.id}
              onClick={() => setActiveMethod(method.id)}
              className={`px-4 py-2 rounded-lg font-medium text-sm transition-all flex items-center gap-2 ${
                activeMethod === method.id
                  ? 'bg-cyan-500/20 border border-cyan-500/50 text-cyan-400'
                  : 'bg-slate-800 border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600'
              }`}
            >
              <span>{method.icon}</span>
              {method.name}
            </button>
          ))}
        </div>

        {/* Install command */}
        <div className="max-w-3xl mx-auto mb-16">
          <div className="bg-slate-900 rounded-2xl border border-slate-800 overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 bg-slate-800/50 border-b border-slate-700">
              <div className="flex items-center gap-3">
                <div className="flex gap-2">
                  <div className="w-3 h-3 rounded-full bg-red-500" />
                  <div className="w-3 h-3 rounded-full bg-yellow-500" />
                  <div className="w-3 h-3 rounded-full bg-green-500" />
                </div>
                <span className="text-sm text-slate-500">{currentMethod.name} Installation</span>
              </div>
              <button
                onClick={() => copyToClipboard(currentMethod.command)}
                className="flex items-center gap-2 px-3 py-1 rounded-lg bg-slate-700 hover:bg-slate-600 text-slate-300 text-sm transition-colors"
              >
                {copiedCommand === currentMethod.command ? (
                  <>
                    <svg className="w-4 h-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                    </svg>
                    Copied!
                  </>
                ) : (
                  <>
                    <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                      <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                    </svg>
                    Copy
                  </>
                )}
              </button>
            </div>
            <div className="p-6">
              <pre className="font-mono text-sm md:text-base overflow-x-auto">
                <span className="text-emerald-400">$</span>{' '}
                <span className="text-white">{currentMethod.command}</span>
              </pre>
              <p className="mt-4 text-sm text-slate-500">{currentMethod.description}</p>
            </div>
          </div>
        </div>

        {/* Usage examples */}
        <div className="mb-16">
          <h3 className="text-2xl font-bold text-white text-center mb-8">Usage Examples</h3>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
            {usageExamples.map((example, i) => (
              <div
                key={i}
                className="bg-slate-800/50 rounded-xl border border-slate-700 p-4 hover:border-slate-600 transition-colors group"
              >
                <div className="flex items-center justify-between mb-2">
                  <h4 className="font-semibold text-white text-sm">{example.title}</h4>
                  <button
                    onClick={() => copyToClipboard(example.command)}
                    className="opacity-0 group-hover:opacity-100 p-1 rounded hover:bg-slate-700 transition-all"
                  >
                    {copiedCommand === example.command ? (
                      <svg className="w-4 h-4 text-emerald-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                      </svg>
                    ) : (
                      <svg className="w-4 h-4 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                        <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    )}
                  </button>
                </div>
                <code className="block text-xs font-mono text-cyan-400 bg-slate-900 rounded p-2 mb-2 overflow-x-auto">
                  {example.command}
                </code>
                <p className="text-xs text-slate-500">{example.description}</p>
              </div>
            ))}
          </div>
        </div>

        {/* CLI Reference */}
        <div className="bg-slate-800/50 rounded-2xl border border-slate-700 overflow-hidden">
          <div className="px-6 py-4 border-b border-slate-700">
            <h3 className="text-lg font-semibold text-white">CLI Reference</h3>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-slate-900/50">
                  <th className="text-left py-3 px-6 text-slate-400 font-medium">Flag</th>
                  <th className="text-left py-3 px-6 text-slate-400 font-medium">Values</th>
                  <th className="text-left py-3 px-6 text-slate-400 font-medium">Description</th>
                </tr>
              </thead>
              <tbody>
                {cliFlags.map((flag, i) => (
                  <tr key={i} className="border-b border-slate-800 hover:bg-slate-800/50 transition-colors">
                    <td className="py-3 px-6">
                      <code className="text-cyan-400 font-mono">{flag.flag}</code>
                    </td>
                    <td className="py-3 px-6">
                      <span className="text-slate-400">{flag.values || '—'}</span>
                    </td>
                    <td className="py-3 px-6 text-slate-300">{flag.description}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Scan Profiles */}
        <div className="mt-12 grid md:grid-cols-4 gap-4">
          {[
            { name: 'quick', description: 'TLS 443 only', time: '~10s', color: 'emerald' },
            { name: 'standard', description: 'TLS + SSH + certs', time: '~30s', color: 'blue' },
            { name: 'deep', description: 'Full enumeration', time: '~5min', color: 'purple' },
            { name: 'compliance', description: 'CNSA 2.0 check', time: '~2min', color: 'orange' },
          ].map((profile) => (
            <div
              key={profile.name}
              className={`bg-${profile.color}-500/10 rounded-xl border border-${profile.color}-500/30 p-4 text-center`}
            >
              <div className={`text-lg font-mono font-bold text-${profile.color}-400 mb-1`}>
                --profile {profile.name}
              </div>
              <div className="text-sm text-slate-400 mb-2">{profile.description}</div>
              <div className="text-xs text-slate-500">Est. time: {profile.time}</div>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}
