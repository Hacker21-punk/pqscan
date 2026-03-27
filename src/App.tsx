import Header from './components/Header';
import Hero from './components/Hero';
import Features from './components/Features';
import HowItWorks from './components/HowItWorks';
import Scanners from './components/Scanners';
import RiskClassification from './components/RiskClassification';
import Algorithms from './components/Algorithms';
import Compliance from './components/Compliance';
import Installation from './components/Installation';
import Architecture from './components/Architecture';
import CTA from './components/CTA';
import Footer from './components/Footer';

export default function App() {
  return (
    <div className="min-h-screen bg-slate-950">
      <Header />
      <main>
        <Hero />
        <Features />
        <HowItWorks />
        <Scanners />
        <RiskClassification />
        <Algorithms />
        <Compliance />
        <Installation />
        <Architecture />
        <CTA />
      </main>
      <Footer />
    </div>
  );
}
