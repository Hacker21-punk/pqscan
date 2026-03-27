import { useState } from 'react';

export default function CTA() {
  const [copied, setCopied] = useState(false);
  const installCommand = 'curl -sSfL https://pqscan.io/install.sh | sh';

  const copyCommand = () => {
    navigator.clipboard.writeText(installCommand);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <section className="py-24 bg-slate-950 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-b from-slate-900 to-slate-950" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[800px] h-[800px] bg-gradient-to-r from-cyan-500/10 via-blue-500/10 to-purple-500/10 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-4xl mx-auto px-4 sm:px-6 lg:px-8 text-center">
        {/* Headline */}
        <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
          Ready to Find Your{' '}
          <span className="bg-gradient-to-r from-red-500 to-orange-500 bg-clip-text text-transparent">
            Quantum Vulnerabilities
          </span>
          ?
        </h2>
        
        <p className="text-lg text-slate-400 mb-10 max-w-2xl mx-auto">
          Start scanning in seconds. Open source, free forever, no account required.
        </p>

        {/* Quick install */}
        <div className="bg-slate-900 rounded-2xl border border-slate-800 p-2 mb-8 max-w-xl mx-auto">
          <div className="flex items-center gap-2">
            <div className="flex-1 bg-slate-800 rounded-xl px-4 py-3 font-mono text-sm text-left overflow-x-auto">
              <span className="text-emerald-400">$</span>{' '}
              <span className="text-white">{installCommand}</span>
            </div>
            <button
              onClick={copyCommand}
              className="btn-press flex-shrink-0 px-4 py-3 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold hover:from-cyan-400 hover:to-blue-500 transition-all"
            >
              {copied ? (
                <span className="flex items-center gap-2">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                  Copied!
                </span>
              ) : (
                <span className="flex items-center gap-2">
                  <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                  </svg>
                  Copy
                </span>
              )}
            </button>
          </div>
        </div>

        {/* Action buttons */}
        <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12">
          <a
            href="https://github.com/pqscan/pqscan"
            target="_blank"
            rel="noopener noreferrer"
            className="btn-press inline-flex items-center gap-3 px-6 py-3 rounded-xl bg-slate-800 border border-slate-700 text-white font-semibold hover:bg-slate-700 hover:border-slate-600 transition-all"
          >
            <svg className="w-5 h-5" fill="currentColor" viewBox="0 0 24 24">
              <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
            </svg>
            Star on GitHub
            <span className="px-2 py-0.5 rounded bg-slate-700 text-xs">2.4k</span>
          </a>
          <a
            href="#install"
            className="btn-press inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-slate-800 border border-slate-700 text-white font-semibold hover:bg-slate-700 hover:border-slate-600 transition-all"
          >
            <svg className="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
            </svg>
            Documentation
          </a>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-12">
          {[
            { value: '2.4k+', label: 'GitHub Stars' },
            { value: '500+', label: 'Daily Downloads' },
            { value: '50+', label: 'Contributors' },
            { value: '99.9%', label: 'Uptime' },
          ].map((stat, i) => (
            <div key={i} className="text-center">
              <div className="text-2xl md:text-3xl font-bold text-white">{stat.value}</div>
              <div className="text-sm text-slate-500">{stat.label}</div>
            </div>
          ))}
        </div>

        {/* Enterprise callout */}
        <div className="bg-gradient-to-r from-purple-500/10 via-blue-500/10 to-cyan-500/10 rounded-2xl border border-slate-700 p-8">
          <div className="flex flex-col md:flex-row items-center justify-between gap-6">
            <div className="text-left">
              <h3 className="text-xl font-bold text-white mb-2">
                Need Enterprise Features?
              </h3>
              <p className="text-slate-400">
                Automated remediation, SSO, priority support, and custom integrations.
              </p>
            </div>
            <a
              href="mailto:enterprise@pqscan.io"
              className="btn-press flex-shrink-0 inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-gradient-to-r from-purple-500 to-blue-600 text-white font-semibold hover:from-purple-400 hover:to-blue-500 transition-all shadow-lg shadow-purple-500/25"
            >
              Contact Sales
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </a>
          </div>
        </div>
      </div>
    </section>
  );
}
