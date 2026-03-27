import { useState, useEffect, useRef } from 'react';

const steps = [
  {
    number: '01',
    title: 'Initialize',
    description: 'Parse configuration, validate targets, set up worker pool and result channels.',
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M5.25 5.653c0-.856.917-1.398 1.667-.986l11.54 6.348a1.125 1.125 0 010 1.971l-11.54 6.347a1.125 1.125 0 01-1.667-.985V5.653z" />
      </svg>
    ),
    details: ['Load config file', 'Set concurrency limits', 'Initialize rate limiter'],
    color: 'cyan',
  },
  {
    number: '02',
    title: 'Discover',
    description: 'Enumerate subdomains, query CT logs, scan ports, and fingerprint services.',
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-5.197-5.197m0 0A7.5 7.5 0 105.196 5.196a7.5 7.5 0 0010.607 10.607z" />
      </svg>
    ),
    details: ['DNS brute-force', 'Certificate Transparency', 'Port scanning'],
    color: 'blue',
  },
  {
    number: '03',
    title: 'Scan',
    description: 'Connect to each endpoint with protocol-specific scanners running in parallel.',
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M7.5 3.75H6A2.25 2.25 0 003.75 6v1.5M16.5 3.75H18A2.25 2.25 0 0120.25 6v1.5m0 9V18A2.25 2.25 0 0118 20.25h-1.5m-9 0H6A2.25 2.25 0 013.75 18v-1.5M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      </svg>
    ),
    details: ['TLS, SSH, IPSec', 'STARTTLS protocols', 'Certificate analysis'],
    color: 'purple',
  },
  {
    number: '04',
    title: 'Classify',
    description: 'Run findings through the classification engine, calculate risk scores and compliance.',
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M9.75 3.104v5.714a2.25 2.25 0 01-.659 1.591L5 14.5M9.75 3.104c-.251.023-.501.05-.75.082m.75-.082a24.301 24.301 0 014.5 0m0 0v5.714c0 .597.237 1.17.659 1.591L19.8 15.3M14.25 3.104c.251.023.501.05.75.082M19.8 15.3l-1.57.393A9.065 9.065 0 0112 15a9.065 9.065 0 00-6.23-.693L5 14.5m14.8.8l1.402 1.402c1.232 1.232.65 3.318-1.067 3.611A48.309 48.309 0 0112 21c-2.773 0-5.491-.235-8.135-.687-1.718-.293-2.3-2.379-1.067-3.61L5 14.5" />
      </svg>
    ),
    details: ['Quantum threat analysis', 'CNSA 2.0 compliance', 'HNDL risk assessment'],
    color: 'orange',
  },
  {
    number: '05',
    title: 'Report',
    description: 'Generate beautiful reports in your preferred format with actionable recommendations.',
    icon: (
      <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={1.5}>
        <path strokeLinecap="round" strokeLinejoin="round" d="M19.5 14.25v-2.625a3.375 3.375 0 00-3.375-3.375h-1.5A1.125 1.125 0 0113.5 7.125v-1.5a3.375 3.375 0 00-3.375-3.375H8.25m2.25 0H5.625c-.621 0-1.125.504-1.125 1.125v17.25c0 .621.504 1.125 1.125 1.125h12.75c.621 0 1.125-.504 1.125-1.125V11.25a9 9 0 00-9-9z" />
      </svg>
    ),
    details: ['CLI, JSON, HTML', 'PDF, SARIF, CBOM', 'CI/CD exit codes'],
    color: 'green',
  },
];

const colorMap: Record<string, string> = {
  cyan: 'from-cyan-500 to-cyan-400',
  blue: 'from-blue-500 to-blue-400',
  purple: 'from-purple-500 to-purple-400',
  orange: 'from-orange-500 to-orange-400',
  green: 'from-emerald-500 to-emerald-400',
};

export default function HowItWorks() {
  const [activeStep, setActiveStep] = useState(0);
  const [isAutoPlaying, setIsAutoPlaying] = useState(true);
  const sectionRef = useRef<HTMLElement>(null);
  const [isVisible, setIsVisible] = useState(false);

  useEffect(() => {
    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setIsVisible(true);
        }
      },
      { threshold: 0.3 }
    );

    if (sectionRef.current) {
      observer.observe(sectionRef.current);
    }

    return () => observer.disconnect();
  }, []);

  useEffect(() => {
    if (!isAutoPlaying || !isVisible) return;

    const interval = setInterval(() => {
      setActiveStep((prev) => (prev + 1) % steps.length);
    }, 3000);

    return () => clearInterval(interval);
  }, [isAutoPlaying, isVisible]);

  const handleStepClick = (index: number) => {
    setActiveStep(index);
    setIsAutoPlaying(false);
    setTimeout(() => setIsAutoPlaying(true), 10000);
  };

  return (
    <section ref={sectionRef} id="how-it-works" className="py-24 bg-slate-900 relative overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0">
        <div className="absolute inset-0 bg-gradient-to-b from-slate-950 via-slate-900 to-slate-950" />
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-purple-500/5 rounded-full blur-3xl" />
      </div>

      <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        {/* Section header */}
        <div className="text-center mb-16">
          <span className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-blue-500/10 border border-blue-500/30 text-blue-400 text-sm font-medium mb-6">
            <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M13 10V3L4 14h7v7l9-11h-7z" />
            </svg>
            Simple Yet Powerful
          </span>
          <h2 className="text-3xl md:text-5xl font-bold text-white mb-4">
            How <span className="text-cyan-400">pqscan</span> Works
          </h2>
          <p className="text-lg text-slate-400 max-w-2xl mx-auto">
            Five steps from installation to actionable quantum risk report. 
            Designed for speed and comprehensive coverage.
          </p>
        </div>

        <div className="grid lg:grid-cols-2 gap-12 items-center">
          {/* Steps list */}
          <div className="space-y-4">
            {steps.map((step, index) => (
              <button
                key={index}
                onClick={() => handleStepClick(index)}
                className={`w-full text-left p-4 rounded-xl border transition-all duration-300 ${
                  activeStep === index
                    ? 'bg-slate-800/80 border-cyan-500/50 shadow-lg shadow-cyan-500/10'
                    : 'bg-slate-800/30 border-slate-700/50 hover:bg-slate-800/50 hover:border-slate-600'
                }`}
              >
                <div className="flex items-start gap-4">
                  {/* Number badge */}
                  <div className={`flex-shrink-0 w-10 h-10 rounded-lg flex items-center justify-center text-sm font-bold transition-all ${
                    activeStep === index
                      ? `bg-gradient-to-br ${colorMap[step.color]} text-white`
                      : 'bg-slate-700 text-slate-400'
                  }`}>
                    {step.number}
                  </div>
                  
                  <div className="flex-1 min-w-0">
                    <h3 className={`font-semibold mb-1 transition-colors ${
                      activeStep === index ? 'text-white' : 'text-slate-300'
                    }`}>
                      {step.title}
                    </h3>
                    <p className="text-sm text-slate-500 line-clamp-2">
                      {step.description}
                    </p>
                  </div>

                  {/* Progress indicator */}
                  {activeStep === index && isAutoPlaying && (
                    <div className="flex-shrink-0 w-8 h-8 rounded-full border-2 border-cyan-500/30 flex items-center justify-center">
                      <div className="w-5 h-5 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
                    </div>
                  )}
                </div>
              </button>
            ))}
          </div>

          {/* Active step detail */}
          <div className="relative">
            <div className="bg-slate-800/50 rounded-2xl border border-slate-700 p-8 backdrop-blur-sm">
              {/* Icon */}
              <div className={`w-16 h-16 rounded-2xl bg-gradient-to-br ${colorMap[steps[activeStep].color]} flex items-center justify-center text-white mb-6 shadow-lg`}>
                {steps[activeStep].icon}
              </div>

              {/* Title and description */}
              <h3 className="text-2xl font-bold text-white mb-3">
                Step {steps[activeStep].number}: {steps[activeStep].title}
              </h3>
              <p className="text-slate-400 mb-6">
                {steps[activeStep].description}
              </p>

              {/* Details list */}
              <div className="space-y-3">
                {steps[activeStep].details.map((detail, i) => (
                  <div 
                    key={i} 
                    className="flex items-center gap-3 text-slate-300"
                    style={{ animationDelay: `${i * 100}ms` }}
                  >
                    <div className={`w-2 h-2 rounded-full bg-gradient-to-r ${colorMap[steps[activeStep].color]}`} />
                    {detail}
                  </div>
                ))}
              </div>

              {/* Terminal preview for scan step */}
              {activeStep === 2 && (
                <div className="mt-6 rounded-lg bg-slate-900 border border-slate-700 p-4 font-mono text-xs">
                  <div className="flex items-center gap-2 text-slate-500 mb-2">
                    <span className="animate-spin">⠋</span>
                    <span>Scanning endpoints...</span>
                  </div>
                  <div className="text-slate-400">
                    <span className="text-emerald-400">✓</span> TLS 1.3 — ECDHE-X25519 — AES-256-GCM
                  </div>
                  <div className="text-slate-400">
                    <span className="text-emerald-400">✓</span> SSH — curve25519-sha256 — chacha20-poly1305
                  </div>
                  <div className="text-slate-400">
                    <span className="text-red-400">✗</span> TLS 1.2 — RSA-2048 — <span className="text-red-400">QUANTUM VULNERABLE</span>
                  </div>
                </div>
              )}

              {/* Progress indicator */}
              <div className="mt-8 flex items-center gap-2">
                {steps.map((_, i) => (
                  <button
                    key={i}
                    onClick={() => handleStepClick(i)}
                    className={`h-1.5 rounded-full transition-all duration-300 ${
                      i === activeStep 
                        ? 'w-8 bg-cyan-400' 
                        : 'w-1.5 bg-slate-600 hover:bg-slate-500'
                    }`}
                  />
                ))}
              </div>
            </div>

            {/* Decorative elements */}
            <div className="absolute -top-4 -right-4 w-24 h-24 bg-gradient-to-br from-cyan-500/20 to-purple-500/20 rounded-full blur-2xl" />
            <div className="absolute -bottom-4 -left-4 w-32 h-32 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-full blur-2xl" />
          </div>
        </div>
      </div>
    </section>
  );
}
