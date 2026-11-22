import { useEffect, useState } from 'react'
import { Link, NavLink, useLocation } from 'react-router-dom'
import { ArrowUpRight, Compass, Menu, X } from 'lucide-react'
import { useTour } from '../tour/Tour'
import { api } from '../lib/api'

export function Logo({ className = '' }) {
  return (
    <Link to="/" className={`group flex items-center gap-2.5 ${className}`}>
      <svg width="26" height="26" viewBox="0 0 32 32" className="transition-transform duration-500 group-hover:rotate-12">
        <circle cx="9" cy="16" r="3.2" fill="#B4FF39" />
        <circle cx="23" cy="8.5" r="2.6" fill="#B4FF39" opacity=".5" />
        <circle cx="23" cy="23.5" r="3.2" fill="#FF4D5E" />
        <path d="M11.8 14.8l8.6-5M11.8 17.2l8.6 5" stroke="#B4FF39" strokeWidth="1.7" strokeLinecap="round" />
      </svg>
      <span className="font-display text-[15px] font-medium tracking-tight text-fog-50">
        Reach<span className="text-lime">Prioritizer</span>
      </span>
    </Link>
  )
}

const LINKS = [
  { to: '/', label: 'Overview', end: true },
  { to: '/scans', label: 'Scans' },
  { to: '/research', label: 'Model & Research' },
  { to: '/learn', label: 'Learn' },
]

function ApiStatus() {
  const [ok, setOk] = useState(null)
  useEffect(() => {
    let alive = true
    const check = () => api.health().then((h) => alive && setOk(h.status === 'healthy')).catch(() => alive && setOk(false))
    check()
    const id = setInterval(check, 15000)
    return () => { alive = false; clearInterval(id) }
  }, [])
  const color = ok == null ? 'bg-fog-500' : ok ? 'bg-lime' : 'bg-risk-critical'
  return (
    <span data-tour="api-status" className="hidden items-center gap-2 font-mono text-[10px] uppercase tracking-[0.18em] text-fog-400 xl:flex" title={ok ? 'API connected' : 'API unreachable'}>
      <span className="relative flex h-2 w-2">
        {ok && <span className="absolute inline-flex h-full w-full rounded-full bg-lime animate-pulse-ring" />}
        <span className={`relative inline-flex h-2 w-2 rounded-full ${color}`} />
      </span>
      {ok == null ? 'connecting' : ok ? 'engine online' : 'api offline'}
    </span>
  )
}

export default function Layout({ children }) {
  const [open, setOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const loc = useLocation()
  useEffect(() => setOpen(false), [loc.pathname])
  useEffect(() => {
    const on = () => setScrolled(window.scrollY > 12)
    window.addEventListener('scroll', on, { passive: true })
    return () => window.removeEventListener('scroll', on)
  }, [])
  const fullBleed = /\/graph$/.test(loc.pathname)
  const { start } = useTour()

  return (
    <div className="relative min-h-screen">
      <div className="pointer-events-none fixed inset-x-0 top-0 h-[520px] grid-lines opacity-60" />
      <header className={`fixed inset-x-0 top-0 z-50 transition-all duration-300 ${scrolled ? 'border-b border-white/[0.06] bg-ink-950/80 py-3 backdrop-blur-xl' : 'py-5'}`}>
        <div className="mx-auto flex max-w-7xl items-center justify-between px-5 md:px-8">
          <Logo />
          <nav data-tour="nav" className={`hidden items-center gap-1 rounded-full border border-white/[0.08] bg-ink-900/70 p-1 backdrop-blur-xl md:flex ${scrolled ? 'shadow-card' : ''}`}>
            {LINKS.map((l) => (
              <NavLink key={l.to} to={l.to} end={l.end}
                className={({ isActive }) => `relative rounded-full px-4 py-1.5 text-[13px] transition-colors ${isActive ? 'bg-white/[0.08] text-fog-50' : 'text-fog-400 hover:text-fog-50'}`}>
                {({ isActive }) => (<>{isActive && <span className="absolute left-2 top-1/2 h-1 w-1 -translate-y-1/2 rounded-full bg-lime" />}{l.label}</>)}
              </NavLink>
            ))}
          </nav>
          <div className="flex items-center gap-4">
            <ApiStatus />
            <button onClick={start} className="hidden items-center gap-2 rounded-full border border-white/10 bg-ink-900/70 px-3.5 py-2 text-[13px] text-fog-300 backdrop-blur-xl transition hover:border-lime/40 hover:text-lime md:inline-flex" title="Guided tour of the website">
              <Compass size={14} /> Tour
            </button>
            <Link data-tour="new-scan" to="/scan/new" className="group hidden items-center gap-3 rounded-full border border-white/10 bg-ink-900/70 py-1 pl-4 pr-1 text-[13px] text-fog-50 backdrop-blur-xl transition hover:border-lime/40 md:inline-flex">
              New scan
              <span className="flex h-7 w-7 items-center justify-center rounded-full bg-lime text-ink-950 shadow-glow-sm transition-transform group-hover:rotate-45">
                <ArrowUpRight size={15} />
              </span>
            </Link>
            <button className="rounded-full border border-white/10 p-2 text-fog-100 md:hidden" onClick={() => setOpen((o) => !o)} aria-label="Menu">
              {open ? <X size={18} /> : <Menu size={18} />}
            </button>
          </div>
        </div>
        {open && (
          <div className="mx-5 mt-3 rounded-2xl border border-white/10 bg-ink-900/95 p-2 backdrop-blur-xl md:hidden">
            {[...LINKS, { to: '/scan/new', label: 'New scan' }].map((l) => (
              <NavLink key={l.to} to={l.to} end={l.end} className={({ isActive }) => `block rounded-xl px-4 py-3 text-sm ${isActive ? 'bg-white/[0.06] text-lime' : 'text-fog-300'}`}>{l.label}</NavLink>
            ))}
            <button onClick={() => { setOpen(false); start() }} className="block w-full rounded-xl px-4 py-3 text-left text-sm text-fog-300">Take the tour</button>
          </div>
        )}
      </header>
      <main className={fullBleed ? 'relative pt-24' : 'relative mx-auto max-w-7xl px-5 pb-24 pt-32 md:px-8'}>{children}</main>
      {!fullBleed && (
        <footer className="relative border-t border-white/[0.06]">
          <div className="mx-auto flex max-w-7xl flex-col items-start justify-between gap-4 px-5 py-8 text-xs text-fog-500 md:flex-row md:items-center md:px-8">
            <Logo />
            <span className="font-mono uppercase tracking-[0.18em]">Static analysis only · source code is never executed</span>
            <span>Research prototype · v2.0</span>
          </div>
        </footer>
      )}
    </div>
  )
}
