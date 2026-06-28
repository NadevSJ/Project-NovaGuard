import { Link } from 'react-router-dom'
import { Shield, Link2, MessageSquare, Mail, Camera, ChevronRight } from 'lucide-react'

const features = [
  {
    icon: <Link2 size={22} className="text-nova-orange" />,
    title: 'URL Inspection',
    desc: 'Sandboxed browser opens suspicious links and checks for phishing forms, redirects, and brand impersonation.',
  },
  {
    icon: <MessageSquare size={22} className="text-nova-orange" />,
    title: 'SMS / Chat Analysis',
    desc: 'Detects fake BOC, Sampath, and Dialog alerts, overseas job lures, and investment scam patterns.',
  },
  {
    icon: <Camera size={22} className="text-nova-orange" />,
    title: 'Screenshot OCR',
    desc: 'Upload a screenshot — NovaGuard extracts the text with Gemini Vision and investigates automatically.',
  },
  {
    icon: <Mail size={22} className="text-nova-orange" />,
    title: 'Email Analysis',
    desc: 'Paste email header and body to detect phishing, spoofed senders, and malicious payloads.',
  },
]

const stats = [
  { value: '4-Label', label: 'Classification' },
  { value: 'AI Agent', label: 'ReAct + Tools' },
  { value: '🇱🇰', label: 'Made for Sri Lanka' },
]

export default function Landing() {
  return (
    <div className="min-h-screen bg-nova-dark">
      {/* Hero */}
      <section className="relative flex flex-col items-center justify-center min-h-[85vh] px-4 text-center overflow-hidden">
        {/* Glow effects */}
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] bg-nova-orange/5 rounded-full blur-3xl pointer-events-none" />

        <div className="relative z-10 max-w-3xl mx-auto">
          <img
            src="/logo-full.png"
            alt="NovaGuard"
            className="h-40 sm:h-56 mx-auto mb-8 object-contain drop-shadow-2xl"
          />
          <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold text-nova-light mb-4 leading-tight">
            Detect scams before
            <br />
            <span className="text-nova-orange">they detect you</span>
          </h1>
          <p className="text-lg text-nova-muted mb-10 max-w-xl mx-auto leading-relaxed">
            AI-powered scam detection for SMS, links, emails, and screenshots — built for Sri Lanka's threat landscape.
          </p>

          <div className="flex flex-col sm:flex-row gap-4 justify-center">
            <Link to="/register" className="btn-primary text-base px-8 py-3">
              Get Started Free
            </Link>
            <Link to="/login" className="btn-secondary text-base px-8 py-3">
              Sign In
            </Link>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="border-y border-nova-border bg-nova-slate/50">
        <div className="max-w-4xl mx-auto px-4 py-10 grid grid-cols-3 gap-4 text-center">
          {stats.map((s) => (
            <div key={s.label}>
              <p className="text-2xl sm:text-3xl font-bold text-nova-orange">{s.value}</p>
              <p className="text-xs sm:text-sm text-nova-muted mt-1">{s.label}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Features */}
      <section className="max-w-5xl mx-auto px-4 py-20">
        <h2 className="text-2xl sm:text-3xl font-bold text-nova-light text-center mb-3">
          Everything you need to stay safe
        </h2>
        <p className="text-nova-muted text-center mb-12 max-w-xl mx-auto">
          NovaGuard's multi-tool AI agent investigates every angle — from URL content to image OCR.
        </p>
        <div className="grid sm:grid-cols-2 gap-5">
          {features.map((f) => (
            <div
              key={f.title}
              className="card hover:border-nova-orange/40 transition-colors duration-300 group"
            >
              <div className="flex items-start gap-4">
                <div className="shrink-0 p-2.5 rounded-lg bg-nova-orange/10 group-hover:bg-nova-orange/20 transition-colors">
                  {f.icon}
                </div>
                <div>
                  <h3 className="text-base font-semibold text-nova-light mb-1">{f.title}</h3>
                  <p className="text-sm text-nova-muted leading-relaxed">{f.desc}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-nova-border bg-nova-slate/30">
        <div className="max-w-2xl mx-auto px-4 py-20 text-center">
          <Shield size={40} className="text-nova-orange mx-auto mb-4" />
          <h2 className="text-2xl font-bold text-nova-light mb-3">Ready to investigate?</h2>
          <p className="text-nova-muted mb-8">
            Create a free account and start analysing suspicious messages in seconds.
          </p>
          <Link to="/register" className="btn-primary inline-flex items-center gap-2 text-base px-8 py-3">
            Create Account <ChevronRight size={18} />
          </Link>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-nova-border py-8 px-4">
        <div className="max-w-5xl mx-auto flex flex-col sm:flex-row items-center justify-between gap-4">
          <div className="flex items-center gap-2">
            <img src="/logo-text.png" alt="NovaGuard" className="h-6 object-contain" />
          </div>
          <p className="text-xs text-nova-muted">
            NovaGuard — Final Year Research Project · LLM-powered scam detection
          </p>
        </div>
      </footer>
    </div>
  )
}
