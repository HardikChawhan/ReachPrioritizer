import { createContext, useCallback, useContext, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { ArrowLeft, ArrowRight, Compass, X } from 'lucide-react'
import { api } from '../lib/api'
import { buildSteps } from './steps'

const TourContext = createContext({ start: () => {}, active: false })
export const useTour = () => useContext(TourContext)

const SEEN_KEY = 'reachprioritizer.tour.seen.v1'
const PAD = 10

function storage(get, value) {
  try {
    if (get) return window.localStorage.getItem(SEEN_KEY)
    window.localStorage.setItem(SEEN_KEY, value)
  } catch { /* storage unavailable (private mode) */ }
  return null
}

async function loadContext() {
  try {
    const scans = await api.scans()
    const done = scans.find((s) => s.status === 'completed' && (s.summary?.actionable || 0) > 0) ||
      scans.find((s) => s.status === 'completed' && s.finding_count > 0) || scans.find((s) => s.status === 'completed')
    if (!done) return {}
    const findings = await api.findings(done.scan_id)
    const exploitable = findings.filter((f) => f.reachability_status === 'reachable' && f.taint === 'user_input')
    const best = exploitable.find((f) => (f.taint_path || []).length > 1) || exploitable[0] || findings[0]
    return { scanId: done.scan_id, findingId: best ? best.finding_id : null }
  } catch {
    return {}
  }
}

function findTarget(target) {
  if (!target) return null
  const el = document.querySelector(`[data-tour="${target}"]`)
  if (!el) return null
  const r = el.getBoundingClientRect()
  if (r.width < 2 || r.height < 2) return null
  return el
}

function Welcome({ onStart, onClose }) {
  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70 p-5 backdrop-blur-sm animate-fade-up">
      <div className="glass relative w-full max-w-lg overflow-hidden p-8 text-center">
        <div className="pointer-events-none absolute -top-24 left-1/2 h-48 w-72 -translate-x-1/2 rounded-full bg-lime/20 blur-3xl" />
        <div className="relative mx-auto mb-6 w-fit rounded-2xl border border-lime/30 bg-lime/10 p-4 text-lime shadow-glow-sm"><Compass size={28} /></div>
        <div className="relative font-display text-3xl font-light text-fog-50">First time here?</div>
        <p className="relative mt-3 text-sm leading-relaxed text-fog-300">
          Take a 2-minute guided tour. It explains what every page and every number means, using a real scan.
        </p>
        <div className="relative mt-8 flex flex-col justify-center gap-3 sm:flex-row">
          <button className="btn-primary px-6" onClick={onStart}>Start the tour</button>
          <button className="btn-ghost px-6" onClick={onClose}>Maybe later</button>
        </div>
        <div className="relative mt-5 text-xs text-fog-500">You can start it again any time with the "Tour" button.</div>
      </div>
    </div>
  )
}

export function TourProvider({ children }) {
  const navigate = useNavigate()
  const location = useLocation()
  const [steps, setSteps] = useState(null)
  const [index, setIndex] = useState(0)
  const [rect, setRect] = useState(null)
  const [searching, setSearching] = useState(false)
  const [welcome, setWelcome] = useState(false)
  const dirRef = useRef(1)
  const active = !!steps

  useEffect(() => {
    if (!storage(true)) {
      const t = setTimeout(() => setWelcome(true), 900)
      return () => clearTimeout(t)
    }
    return undefined
  }, [])

  const start = useCallback(async () => {
    setWelcome(false)
    storage(false, '1')
    const ctx = await loadContext()
    dirRef.current = 1
    setIndex(0)
    setRect(null)
    setSteps(buildSteps(ctx))
  }, [])

  const stop = useCallback(() => {
    storage(false, '1')
    setSteps(null)
    setRect(null)
  }, [])

  const step = steps ? steps[index] : null

  // navigate to the step's page, then wait for its target element
  useEffect(() => {
    if (!step) return undefined
    if (step.route && location.pathname !== step.route) {
      navigate(step.route)
      return undefined
    }
    let cancelled = false
    let tries = 0
    setSearching(true)
    const look = () => {
      if (cancelled) return
      const el = findTarget(step.target)
      if (el || !step.target) {
        if (el) el.scrollIntoView({ block: 'center', behavior: 'smooth' })
        setTimeout(() => {
          if (cancelled) return
          setRect(el ? el.getBoundingClientRect() : null)
          setSearching(false)
        }, el ? 450 : 0)
        return
      }
      if (++tries > 40) { // ~4 s
        setSearching(false)
        if (step.optional) {
          setIndex((i) => Math.min(Math.max(0, i + dirRef.current), steps.length - 1))
        } else {
          setRect(null)
        }
        return
      }
      setTimeout(look, 100)
    }
    look()
    return () => { cancelled = true }
  }, [step, location.pathname, navigate, steps])

  // keep the spotlight glued to the element while scrolling / resizing
  useLayoutEffect(() => {
    if (!step || !step.target || searching) return undefined
    const update = () => {
      const el = findTarget(step.target)
      if (el) setRect(el.getBoundingClientRect())
    }
    window.addEventListener('resize', update)
    window.addEventListener('scroll', update, true)
    return () => { window.removeEventListener('resize', update); window.removeEventListener('scroll', update, true) }
  }, [step, searching])

  const next = useCallback(() => {
    if (!steps) return
    if (index >= steps.length - 1) { stop(); return }
    dirRef.current = 1
    setRect(null)
    setIndex(index + 1)
  }, [steps, index, stop])

  const back = useCallback(() => {
    if (index === 0) return
    dirRef.current = -1
    setRect(null)
    setIndex(index - 1)
  }, [index])

  useEffect(() => {
    if (!active) return undefined
    const onKey = (e) => {
      if (e.key === 'Escape') stop()
      else if (e.key === 'ArrowRight' || e.key === 'Enter') next()
      else if (e.key === 'ArrowLeft') back()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [active, next, back, stop])

  const value = useMemo(() => ({ start, active }), [start, active])

  // tooltip placement
  let card = { left: '50%', top: '50%', transform: 'translate(-50%, -50%)' }
  const W = Math.min(380, (typeof window !== 'undefined' ? window.innerWidth : 400) - 24)
  if (rect && typeof window !== 'undefined') {
    const vh = window.innerHeight
    const vw = window.innerWidth
    const H = 250 // generous card height estimate
    const left = Math.min(Math.max(12, rect.left + rect.width / 2 - W / 2), vw - W - 12)
    let top
    if (vh - rect.bottom - PAD > H + 16) top = rect.bottom + PAD + 12           // below the target
    else if (rect.top - PAD > H + 16) top = rect.top - PAD - 12 - H              // above the target
    else top = vh - H - 16                                                      // overlap, pinned to bottom
    card = { left, top: Math.max(12, Math.min(top, vh - H - 16)) }
  }

  return (
    <TourContext.Provider value={value}>
      {children}
      {welcome && !active && <Welcome onStart={start} onClose={() => { setWelcome(false); storage(false, '1') }} />}
      {active && step && (
        <div className="fixed inset-0 z-[100]" aria-live="polite">
          {/* dim layer with a hole around the target */}
          {rect ? (
            <div
              className="pointer-events-none fixed rounded-2xl transition-all duration-300 ease-out"
              style={{
                left: rect.left - PAD, top: rect.top - PAD, width: rect.width + PAD * 2, height: rect.height + PAD * 2,
                boxShadow: '0 0 0 9999px rgba(2,3,2,0.74), 0 0 0 1.5px rgba(180,255,57,0.85), 0 0 40px 4px rgba(180,255,57,0.25)',
              }}
            />
          ) : (
            <div className="fixed inset-0 bg-[rgba(2,3,2,0.74)] transition-opacity" />
          )}
          <div className="fixed inset-0" onClick={(e) => e.stopPropagation()} />
          {!searching && (
            <div role="dialog" aria-label={step.title} className="glass fixed animate-fade-up border-lime/25 p-5 shadow-glow" style={{ width: W, ...card }}>
              <div className="flex items-center justify-between">
                <span className="font-mono text-[10px] uppercase tracking-[0.2em] text-lime">Step {index + 1} / {steps.length}</span>
                <button onClick={stop} className="rounded-lg p-1 text-fog-400 hover:bg-white/5 hover:text-fog-50" aria-label="Close tour"><X size={15} /></button>
              </div>
              <div className="mt-3 font-display text-xl text-fog-50">{step.title}</div>
              <p className="mt-2 text-sm leading-relaxed text-fog-300">{step.body}</p>
              <div className="mt-4 h-1 overflow-hidden rounded-full bg-white/[0.06]">
                <div className="h-full rounded-full bg-lime transition-all duration-500" style={{ width: `${((index + 1) / steps.length) * 100}%` }} />
              </div>
              <div className="mt-4 flex items-center justify-between">
                <button onClick={stop} className="text-xs text-fog-500 hover:text-fog-200">Skip tour</button>
                <div className="flex gap-2">
                  <button onClick={back} disabled={index === 0} className="btn-ghost px-3 py-1.5 text-xs"><ArrowLeft size={13} /> Back</button>
                  <button onClick={next} className="btn-primary px-4 py-1.5 text-xs">{index === steps.length - 1 ? 'Finish' : <>Next <ArrowRight size={13} /></>}</button>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </TourContext.Provider>
  )
}
