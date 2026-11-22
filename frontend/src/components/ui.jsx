import { useCallback, useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { AlertTriangle, Loader2, RefreshCw } from 'lucide-react'
import { REACH, RISK, TAINT, riskOf } from '../lib/format'

/** [ LABEL ] in mono lime — the signature element of the design */
export function Label({ children, className = '' }) {
  return <div className={`label-bracket ${className}`}>[ {children} ]</div>
}

export function Card({ children, className = '', hover = false, as: As = 'div', ...rest }) {
  return (
    <As className={`glass ${hover ? 'glass-hover' : ''} ${className}`} {...rest}>
      {children}
    </As>
  )
}

export function PageHeader({ label, title, fade, children, className = '' }) {
  return (
    <div className={`flex flex-col gap-6 md:flex-row md:items-end md:justify-between animate-fade-up ${className}`}>
      <div className="min-w-0">
        {label && <Label className="mb-4">{label}</Label>}
        <h1 className="font-display text-4xl font-light leading-[1.05] tracking-tight text-fog-50 md:text-5xl">
          {title} {fade && <span className="text-fade">{fade}</span>}
        </h1>
      </div>
      {children && <div className="flex flex-wrap items-center gap-3">{children}</div>}
    </div>
  )
}

export function StatTile({ label, value, sub, accent = false, icon: Icon, tone }) {
  const toneCls = tone === 'danger' ? 'text-risk-critical' : tone === 'warn' ? 'text-risk-high' : accent ? 'text-lime' : 'text-fog-50'
  return (
    <Card className="relative overflow-hidden p-5">
      {accent && <div className="pointer-events-none absolute -right-10 -top-10 h-32 w-32 rounded-full bg-lime/10 blur-2xl" />}
      <div className="flex items-center justify-between">
        <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-fog-400">{label}</span>
        {Icon && <Icon size={16} className={accent ? 'text-lime' : 'text-fog-500'} />}
      </div>
      <div className={`mt-3 font-display text-4xl font-light tabular-nums ${toneCls}`}>{value}</div>
      {sub && <div className="mt-1 text-xs text-fog-400">{sub}</div>}
    </Card>
  )
}

/** Circular risk score gauge */
export function RiskRing({ score = 0, size = 56, stroke = 5, showLabel = false }) {
  const cat = riskOf(score)
  const color = RISK[cat].color
  const r = (size - stroke) / 2
  const c = 2 * Math.PI * r
  const off = c * (1 - Math.min(100, Math.max(0, score)) / 100)
  return (
    <div className="relative shrink-0" style={{ width: size, height: size }} title={`Risk ${score.toFixed(1)} / 100 (${cat})`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} stroke="rgba(255,255,255,0.07)" strokeWidth={stroke} fill="none" />
        <circle cx={size / 2} cy={size / 2} r={r} stroke={color} strokeWidth={stroke} fill="none" strokeLinecap="round"
          strokeDasharray={c} strokeDashoffset={off} style={{ filter: `drop-shadow(0 0 6px ${color}88)`, transition: 'stroke-dashoffset 0.8s ease' }} />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="font-display tabular-nums text-fog-50" style={{ fontSize: size * 0.3 }}>{Math.round(score)}</span>
        {showLabel && <span className="font-mono text-[9px] uppercase tracking-widest" style={{ color }}>{cat}</span>}
      </div>
    </div>
  )
}

const TONES = {
  danger: 'border-risk-critical/35 bg-risk-critical/10 text-[#ff8a95]',
  warn: 'border-risk-high/30 bg-risk-high/10 text-[#ffb27a]',
  muted: 'border-white/10 bg-white/[0.04] text-fog-400',
  lime: 'border-lime/35 bg-lime/10 text-lime',
}

export function Pill({ tone = 'muted', children, title, dot = false, className = '' }) {
  return (
    <span title={title} className={`inline-flex items-center gap-1.5 whitespace-nowrap rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${TONES[tone]} ${className}`}>
      {dot && <span className="h-1.5 w-1.5 rounded-full bg-current" />}
      {children}
    </span>
  )
}

export function RiskBadge({ category }) {
  const r = RISK[category] || RISK.Low
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider ${r.border} ${r.bg} ${r.text}`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />{category}
    </span>
  )
}

export function ReachBadge({ status }) {
  const r = REACH[status] || REACH.unknown
  return <Pill tone={r.tone} title={r.hint} dot>{r.label}</Pill>
}

export function TaintBadge({ taint }) {
  const t = TAINT[taint] || TAINT.unknown
  return <Pill tone={t.tone} title={t.hint}>{t.label}</Pill>
}

export function Spinner({ size = 18, className = '' }) {
  return <Loader2 size={size} className={`animate-spin text-lime ${className}`} />
}

export function Skeleton({ className = '' }) {
  return <div className={`skeleton ${className}`} />
}

export function ErrorState({ error, onRetry }) {
  return (
    <Card className="flex flex-col items-center gap-4 p-10 text-center">
      <AlertTriangle className="text-risk-high" />
      <div className="max-w-md text-sm text-fog-300">{String(error?.message || error)}</div>
      {onRetry && <button className="btn-ghost" onClick={onRetry}><RefreshCw size={14} /> Try again</button>}
    </Card>
  )
}

export function EmptyState({ icon: Icon, title, children, action }) {
  return (
    <Card className="flex flex-col items-center gap-3 px-6 py-14 text-center">
      {Icon && <div className="mb-2 rounded-2xl border border-lime/20 bg-lime/5 p-4 text-lime"><Icon size={22} /></div>}
      <div className="font-display text-xl text-fog-50">{title}</div>
      {children && <div className="max-w-md text-sm text-fog-400">{children}</div>}
      {action && <div className="mt-3">{action}</div>}
    </Card>
  )
}

export function ProgressBar({ value = 0, className = '' }) {
  return (
    <div className={`h-1.5 w-full overflow-hidden rounded-full bg-white/[0.06] ${className}`}>
      <div className="h-full rounded-full bg-gradient-to-r from-lime-600 via-lime to-lime-200 shadow-glow-sm transition-all duration-700"
        style={{ width: `${Math.max(2, Math.min(100, value))}%` }} />
    </div>
  )
}

/** Horizontal stacked bar for distributions */
export function SegmentBar({ segments, height = 10 }) {
  const total = segments.reduce((s, x) => s + x.value, 0)
  if (!total) return <div className="w-full rounded-full bg-white/[0.05]" style={{ height }} />
  return (
    <div className="flex w-full overflow-hidden rounded-full bg-white/[0.05]" style={{ height }}>
      {segments.filter((s) => s.value > 0).map((s) => (
        <div key={s.label} title={`${s.label}: ${s.value}`} style={{ width: `${(100 * s.value) / total}%`, background: s.color }}
          className="h-full transition-all duration-700 first:rounded-l-full last:rounded-r-full" />
      ))}
    </div>
  )
}

export function BarRow({ label, value, max, color = '#B4FF39', suffix = '', sub }) {
  const w = max ? Math.max(2, (100 * value) / max) : 0
  return (
    <div>
      <div className="mb-1.5 flex items-baseline justify-between gap-3 text-sm">
        <span className="truncate text-fog-300">{label}</span>
        <span className="font-mono text-xs tabular-nums text-fog-100">{value}{suffix}{sub && <span className="ml-2 text-fog-500">{sub}</span>}</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${w}%`, background: color, boxShadow: `0 0 12px ${color}55` }} />
      </div>
    </div>
  )
}

/** Generic data loader with optional polling */
export function useAsync(fn, deps = [], { poll, until } = {}) {
  const [state, setState] = useState({ loading: true, data: null, error: null })
  const fnRef = useRef(fn)
  fnRef.current = fn
  const load = useCallback(async (silent = false) => {
    if (!silent) setState((s) => ({ ...s, loading: true, error: null }))
    try {
      const data = await fnRef.current()
      setState({ loading: false, data, error: null })
      return data
    } catch (error) {
      setState((s) => ({ loading: false, data: s.data, error }))
      return null
    }
  }, [])
  useEffect(() => {
    let timer
    let alive = true
    const run = async (silent) => {
      const data = await load(silent)
      if (alive && poll && !(until && data && until(data))) timer = setTimeout(() => run(true), poll)
    }
    run(false)
    return () => { alive = false; clearTimeout(timer) }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, deps)
  return { ...state, reload: () => load(false), setData: (data) => setState((s) => ({ ...s, data })) }
}

/** Small "?" button that explains a section, with a link into the Learn page. */
export function InfoHint({ title, children, learn, align = 'left' }) {
  const [open, setOpen] = useState(false)
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return undefined
    const close = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false) }
    document.addEventListener('mousedown', close)
    return () => document.removeEventListener('mousedown', close)
  }, [open])
  return (
    <span ref={ref} className="relative inline-flex">
      <button
        type="button"
        aria-label={`What is ${title}?`}
        onClick={() => setOpen((o) => !o)}
        className={`flex h-5 w-5 items-center justify-center rounded-full border text-[10px] font-semibold transition ${open ? 'border-lime/60 bg-lime/15 text-lime' : 'border-white/15 text-fog-400 hover:border-lime/40 hover:text-lime'}`}
      >?</button>
      {open && (
        <span className={`absolute top-7 z-40 w-72 animate-fade-up rounded-xl border border-white/10 bg-ink-850/95 p-4 text-left shadow-card backdrop-blur-xl ${align === 'right' ? 'right-0' : 'left-0'}`}>
          <span className="block font-display text-sm text-fog-50">{title}</span>
          <span className="mt-1.5 block text-xs font-normal normal-case leading-relaxed tracking-normal text-fog-300">{children}</span>
          {learn && <Link to={`/learn#${learn}`} className="mt-3 block text-xs normal-case tracking-normal text-lime hover:underline">Learn more →</Link>}
        </span>
      )}
    </span>
  )
}
