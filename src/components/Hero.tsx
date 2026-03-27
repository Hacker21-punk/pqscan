import { useState, useEffect, useRef } from 'react';

export default function Hero() {
  const [typedText, setTypedText] = useState('');
  const [showResults, setShowResults] = useState(false);
  const [scanProgress, setScanProgress] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);
  const typingRef = useRef<number | null>(null);
  
  const fullText = 'pqscan example.com --profile deep';
  const steps = ['Initializing...', 'Discovering endpoints...', 'Scanning TLS...', 'Analyzing certificates...', 'Classifying risks...'];

  useEffect(() => {
    // Typing animation
    let i = 0;
    typingRef.current = window.setInterval(() => {
      if (i < fullText.length) {
        setTypedText(fullText.slice(0, i + 1));
        i++;
      } else {
        if (typingRef.current) clearInterval(typingRef.current);
        // Start scan animation
        setTimeout(() => startScanAnimation(), 500);
      }
    }, 60);
    
    return () => {
      if (typingRef.current) clearInterval(typingRef.current);
    };
  }, []);

  const startScanAnimation = () => {
    let progress = 0;
    let step = 0;
    const interval = setInterval(() => {
      progress += Math.random() * 8 + 2;
      if (progress >= 100) {
        progress = 100;
        clearInterval(interval);
        setTimeout(() => setShowResults(true), 300);
      }
      setScanProgress(Math.min(progress, 100));
      
      const newStep = Math.floor((progress / 100) * steps.length);
      if (newStep !== step && newStep < steps.length) {
        step = newStep;
        setCurrentStep(step);
      }
    }, 150);
  };

  const scrollToInstall = () => {
    document.getElementById('install')?.scrollIntoView({ behavior: 'smooth' });
  };

  return (
    <section id="home" className="relative min-h-screen flex items-center justify-center overflow-hidden bg-slate-950 pt-16">
      {/* Animated background */}
      <div className="absolute inset-0">
        {/* Grid pattern */}
        <div className="absolute inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_110%)]" />
        
        {/* Gradient orbs */}
        <div className="absolute top-1/4 left-1/4 w-96 h-96 bg-cyan-500/20 rounded-full blur-3xl animate-pulse" />
        <div className="absolute bottom-1/4 right-1/4 w-96 h-96 bg-purple-500/20 rounded-full blur-3xl animate-pulse delay-1000" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-blue-500/10 rounded-full blur-3xl" />
        
        {/* Floating particles */}
        <div className="absolute top-1/3 left-1/5 w-2 h-2 bg-cyan-400/60 rounded-full animate-float" />
        <div className="absolute top-2/3 right-1/4 w-3 h-3 bg-purple-400/60 rounded-full animate-float delay-500" />
        <div className="absolute bottom-1/4 left-1/3 w-2 h-2 bg-blue-400/60 rounded-full animate-float delay-700" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-20">
        <div className="text-center">
          {/* Urgency Badge */}
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-red-500/10 border border-red-500/30 mb-8 animate-fade-in">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-red-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500"></span>
            </span>
            <span className="text-sm text-red-300 font-medium">94% of endpoints are quantum-vulnerable</span>
          </div>

          {/* Headline */}
          <h1 className="text-4xl sm:text-5xl md:text-7xl font-bold text-white mb-6 leading-tight animate-fade-in-up">
            Find It Before The
            <br />
            <span className="bg-gradient-to-r from-red-500 via-orange-500 to-yellow-500 bg-clip-text text-transparent">
              Quantum Computer
            </span>
            <br />
            Does
          </h1>

          {/* Subheadline */}
          <p className="text-lg md:text-xl text-slate-400 max-w-3xl mx-auto mb-4 animate-fade-in-up delay-100">
            Discover and classify every cryptographic algorithm in your infrastructure 
            that will be broken by quantum computers.
          </p>
          <p className="text-base text-slate-500 italic mb-10 animate-fade-in-up delay-200">
            "Harvest Now, Decrypt Later" attacks mean your data is at risk <span className="text-red-400 font-semibold">TODAY</span>.
          </p>

          {/* CTA Buttons */}
          <div className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-12 animate-fade-in-up delay-300">
            <button 
              onClick={scrollToInstall}
              className="btn-press group inline-flex items-center gap-3 px-8 py-4 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 text-white font-semibold text-lg hover:from-cyan-400 hover:to-blue-500 transition-all shadow-xl shadow-blue-500/25 hover:shadow-blue-500/40"
            >
              <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
              </svg>
              Install pqscan
              <svg className="w-5 h-5 group-hover:translate-x-1 transition-transform" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
              </svg>
            </button>
            <a 
              href="https://github.com/pqscan/pqscan" 
              target="_blank" 
              rel="noopener noreferrer" 
              className="btn-press inline-flex items-center gap-3 px-8 py-4 rounded-xl bg-slate-800 border border-slate-700 text-white font-semibold text-lg hover:bg-slate-700 hover:border-slate-600 transition-all"
            >
              <svg className="w-6 h-6" fill="currentColor" viewBox="0 0 24 24">
                <path fillRule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.531 1.032 1.531 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z" clipRule="evenodd" />
              </svg>
              View on GitHub
            </a>
          </div>

          {/* Terminal Preview */}
          <div className="max-w-4xl mx-auto animate-fade-in-up delay-500">
            <div className="rounded-2xl bg-slate-900/90 border border-slate-800 shadow-2xl shadow-black/50 overflow-hidden backdrop-blur-sm">
              {/* Terminal Header */}
              <div className="flex items-center justify-between px-4 py-3 bg-slate-800/80 border-b border-slate-700">
                <div className="flex items-center gap-3">
                  <div className="flex gap-2">
                    <div className="w-3 h-3 rounded-full bg-red-500 hover:bg-red-400 transition-colors cursor-pointer" />
                    <div className="w-3 h-3 rounded-full bg-yellow-500 hover:bg-yellow-400 transition-colors cursor-pointer" />
                    <div className="w-3 h-3 rounded-full bg-green-500 hover:bg-green-400 transition-colors cursor-pointer" />
                  </div>
                  <span className="text-sm text-slate-500 font-mono">pqscan — v0.1.0</span>
                </div>
                <div className="flex items-center gap-2 text-slate-500 text-xs">
                  <span className="hidden sm:inline">Press ⌘+C to copy</span>
                </div>
              </div>
              
              {/* Terminal Content */}
              <div className="p-4 md:p-6 font-mono text-xs md:text-sm overflow-x-auto code-scroll">
                {/* ASCII Banner */}
                <pre className="text-cyan-400 mb-4 text-[9px] sm:text-[10px] md:text-xs leading-tight whitespace-pre">
{`╔═══════════════════════════════════════════════╗
║   ___  ___  ___                               ║
║  | _ \\/ _ \\/ __|  ___ __ _ _ _                ║
║  |  _/ (_) \\__ \\ / _\` | ' \\               ║
║  |_|  \\__\\_\\___/ \\__\\__,_|_||_|              ║
║                                               ║
║  Post-Quantum Cryptography Vulnerability      ║
║  Scanner v0.1.0                               ║
║                                               ║
║  "Find it before the quantum computer does"   ║
╚═══════════════════════════════════════════════╝`}
                </pre>

                {/* Command input */}
                <div className="flex items-center gap-2 text-slate-400 mb-4">
                  <span className="text-emerald-400">$</span>
                  <span className="text-white">{typedText}</span>
                  {!showResults && <span className="animate-pulse text-cyan-400">▋</span>}
                </div>
                
                {/* Progress bar */}
                {!showResults && scanProgress > 0 && (
                  <div className="mb-4">
                    <div className="flex items-center gap-3 text-slate-500 mb-2">
                      <span className="animate-spin">⠋</span>
                      <span>{steps[currentStep]}</span>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="flex-1 h-2 bg-slate-800 rounded-full overflow-hidden">
                        <div 
                          className="h-full bg-gradient-to-r from-cyan-500 to-blue-500 rounded-full transition-all duration-300"
                          style={{ width: `${scanProgress}%` }}
                        />
                      </div>
                      <span className="text-slate-400 text-xs w-12 text-right">{Math.round(scanProgress)}%</span>
                    </div>
                  </div>
                )}
                
                {/* Results Box */}
                {showResults && (
                  <div className="animate-fade-in">
                    <pre className="text-slate-300 text-[9px] sm:text-[10px] md:text-xs leading-relaxed">
{`╔══════════════════════════════════════════════════╗
║          PQScan — Quantum Risk Report            ║
╠══════════════════════════════════════════════════╣
║                                                  ║
║  Target:                    example.com          ║
║  Endpoints scanned:         1,247                ║
║  Quantum-vulnerable:        1,183 (94.8%)        ║
║                                                  ║
║  Risk Score:    `}<span className="text-red-400 font-bold">94.8</span>{` / 100    `}<span className="text-red-400">██████████████</span><span className="text-slate-600">░</span>{` ║
║  CNSA 2.0:      `}<span className="text-red-400">NON-COMPLIANT</span>{`                    ║
║  HNDL Risk:     `}<span className="text-red-400">CRITICAL</span>{`                         ║
║                                                  ║
║  `}<span className="text-red-400">🔴 Critical: 947</span>{`  │  `}<span className="text-yellow-400">🟡 Moderate:  94</span>{`         ║
║  `}<span className="text-orange-400">🟠 High:     142</span>{`  │  `}<span className="text-blue-400">🔵 Low:       61</span>{`         ║
║  `}<span className="text-emerald-400">🟢 Safe:       3</span>{`  │                            ║
║                                                  ║
╚══════════════════════════════════════════════════╝`}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Key stats */}
          <div className="mt-12 grid grid-cols-2 md:grid-cols-4 gap-6 max-w-3xl mx-auto animate-fade-in-up delay-700">
            {[
              { value: '7', label: 'Protocol Scanners' },
              { value: '100+', label: 'Algorithms Tracked' },
              { value: '6', label: 'Output Formats' },
              { value: 'Apache 2.0', label: 'Open Source' },
            ].map((stat, i) => (
              <div key={i} className="text-center p-4 rounded-xl bg-slate-900/50 border border-slate-800 hover:border-slate-700 transition-colors">
                <div className="text-2xl md:text-3xl font-bold text-white mb-1">{stat.value}</div>
                <div className="text-xs md:text-sm text-slate-500">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Scroll indicator */}
      <div className="absolute bottom-8 left-1/2 -translate-x-1/2 animate-bounce">
        <button 
          onClick={() => document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' })}
          className="p-2 text-slate-500 hover:text-slate-300 transition-colors"
          aria-label="Scroll down"
        >
          <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M19 14l-7 7m0 0l-7-7m7 7V3" />
          </svg>
        </button>
      </div>
    </section>
  );
}
