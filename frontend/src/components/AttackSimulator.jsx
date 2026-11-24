import { useEffect, useRef, useState } from 'react'
import { Check, ChevronLeft, ChevronRight, Copy, DoorOpen, Pause, Play, RotateCcw, Send, ShieldOff, Skull, Swords, Waypoints, Zap } from 'lucide-react'
import { Card, InfoHint, Label, Pill } from './ui'
import { prettyFn } from '../lib/format'

const VERDICT = {
  exploitable: { tone: 'danger', label: 'Exploitable', icon: Swords },
  internal: { tone: 'warn', label: 'Internal only', icon: ShieldOff },
  blocked: { tone: 'muted', label: 'Blocked — no route', icon: ShieldOff },
}
const STEP_ICON = { request: Send, hop: Waypoints, sink: Skull, impact: Zap }

function CopyButton({ text }) {
  const [done, setDone] = useState(false)
  const copy = async () => {
    try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1400) } catch { /* clipboard blocked */ }
  }
  return (
    <button type="button" onClick={copy} className="inline-flex items-center gap-1.5 rounded-lg border border-white/10 px-2.5 py-1 text-xs text-fog-300 hover:border-lime/40 hover:text-lime">
      {done ? <Check size={12} /> : <Copy size={12} />}{done ? 'Copied' : 'Copy'}
    </button>
  )
}

/** Show `text` with the first occurrence of `needle` highlighted as the attacker's part. */
function Highlight({ text, needle }) {
  if (!text) return null
  const i = needle ? text.indexOf(needle) : -1
  if (i < 0) return <>{text}</>
  return (
    <>
      {text.slice(0, i)}
      <mark className="rounded bg-risk-critical/25 px-0.5 text-[#ffb3b9] shadow-[0_0_14px_-2px_rgba(255,77,94,0.7)]">{needle}</mark>
      {text.slice(i + needle.length)}
    </>
  )
}

function RequestBox({ request, payload }) {
  const [tab, setTab] = useState('curl')
  const tabs = [['curl', 'curl'], ['fetch', 'JavaScript'], ['raw_http', 'Raw HTTP']]
  const text = request[tab] || ''
  return (
    <div className="overflow-hidden rounded-xl border border-white/10 bg-ink-950/80">
      <div className="flex items-center gap-1 border-b border-white/[0.06] px-2 py-1.5">
        {tabs.map(([k, l]) => (
          <button key={k} type="button" onClick={() => setTab(k)} className={`rounded-md px-2.5 py-1 font-mono text-[11px] ${tab === k ? 'bg-white/[0.07] text-fog-50' : 'text-fog-500 hover:text-fog-300'}`}>{l}</button>
        ))}
        <span className="flex-1" />
        <CopyButton text={text} />
      </div>
      <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-all p-4 font-mono text-[12.5px] leading-relaxed text-fog-200">{text}</pre>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1 border-t border-white/[0.06] px-4 py-2 text-[11px] text-fog-500">
        <span>payload in <span className="text-fog-300">{request.input_location}{request.input_field ? ` · ${request.input_field}` : ''}</span></span>
        <span>value <span className="font-mono text-[#ff8a95]">{payload.length > 48 ? `${payload.slice(0, 45)}…` : payload}</span></span>
        {!request.route_known && <span className="text-risk-high">route guessed</span>}
        {request.route_known && !request.field_known && <span className="text-risk-high">input name guessed</span>}
      </div>
    </div>
  )
}

export default function AttackSimulator({ attack }) {
  const steps = attack.steps || []
  const [shown, setShown] = useState(steps.length)
  const [playing, setPlaying] = useState(false)
  const timer = useRef(null)
  const v = VERDICT[attack.verdict] || VERDICT.blocked
  const blocked = attack.verdict !== 'exploitable'

  useEffect(() => {
    if (!playing) return undefined
    if (shown >= steps.length) { setPlaying(false); return undefined }
    timer.current = setTimeout(() => setShown((n) => n + 1), shown === 0 ? 250 : 950)
    return () => clearTimeout(timer.current)
  }, [playing, shown, steps.length])

  const play = () => { setShown(0); setPlaying(true) }

  return (
    <Card data-tour="attack-sim" className="relative overflow-hidden p-6 md:p-8">
      <div className={`pointer-events-none absolute -left-20 -top-20 h-56 w-56 rounded-full blur-3xl ${blocked ? 'bg-white/5' : 'bg-risk-critical/15'}`} />
      <div className="relative flex flex-wrap items-center gap-3">
        <Swords size={16} className={blocked ? 'text-fog-400' : 'text-risk-critical'} />
        <Label>Attack simulator</Label>
        <InfoHint title="Attack simulator" learn="attack-sim">
          Built from what the engine proved: the route, the input field that reaches the bug and the dangerous line. It shows the request an attacker would send and what the server would execute. Nothing is sent — it is a simulation.
        </InfoHint>
        <Pill tone={v.tone} dot>{v.label}</Pill>
        <Pill title="How sure we are about the exact URL and input name">confidence: {attack.confidence}</Pill>
      </div>
      <p className="relative mt-2 max-w-3xl text-sm text-fog-400">{attack.verdict_text} <span className="text-fog-500">Goal: {attack.goal}.</span></p>

      <div className="relative mt-6 grid gap-6 lg:grid-cols-[1.1fr_1fr]">
        <div className="min-w-0">
          <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-fog-500">The attacker's request</div>
          <RequestBox request={attack.request} payload={attack.payload} />
          {attack.effect && (
            <div className="mt-5">
              <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-fog-500">What the server ends up executing</div>
              <pre className={`overflow-auto whitespace-pre-wrap break-all rounded-xl border p-4 font-mono text-[12.5px] leading-relaxed transition-all duration-500 ${shown >= steps.length - 1 ? 'border-risk-critical/40 bg-risk-critical/[0.06] text-fog-100' : 'border-white/10 bg-ink-950/60 text-fog-500 blur-[2px]'}`}>
                <Highlight text={attack.effect} needle={attack.payload} />
              </pre>
            </div>
          )}
          <p className="mt-4 text-[11px] leading-relaxed text-fog-500">{attack.note}</p>
        </div>

        <div className="min-w-0">
          <div className="mb-2 flex items-center gap-2">
            <span className="font-mono text-[11px] uppercase tracking-[0.16em] text-fog-500">Step-by-step</span>
            <span className="flex-1" />
            <button type="button" className="rounded-lg p-1.5 text-fog-400 hover:bg-white/5 disabled:opacity-30" disabled={shown <= 1} onClick={() => { setPlaying(false); setShown((n) => Math.max(1, n - 1)) }} aria-label="Previous step"><ChevronLeft size={15} /></button>
            <button type="button" className="rounded-lg p-1.5 text-fog-400 hover:bg-white/5 disabled:opacity-30" disabled={shown >= steps.length} onClick={() => { setPlaying(false); setShown((n) => Math.min(steps.length, n + 1)) }} aria-label="Next step"><ChevronRight size={15} /></button>
            <button type="button" data-tour="attack-play" onClick={playing ? () => setPlaying(false) : play}
              className={`inline-flex items-center gap-1.5 rounded-full px-3.5 py-1.5 text-xs font-semibold transition ${blocked ? 'bg-white/10 text-fog-100 hover:bg-white/15' : 'bg-risk-critical text-white shadow-glow-red hover:brightness-110'}`}>
              {playing ? <Pause size={13} /> : shown >= steps.length ? <RotateCcw size={13} /> : <Play size={13} />}
              {playing ? 'Pause' : shown >= steps.length ? 'Replay attack' : 'Play'}
            </button>
          </div>
          <ol className="relative space-y-3">
            <span className="absolute bottom-4 left-[15px] top-4 w-px bg-gradient-to-b from-risk-critical/50 via-white/10 to-transparent" aria-hidden />
            {steps.map((st, i) => {
              const Icon = i === 1 && st.kind === 'hop' ? DoorOpen : STEP_ICON[st.kind] || Waypoints
              const visible = i < shown
              const current = playing && i === shown - 1
              const stopHere = blocked && st.kind === 'hop' && i === 1
              return (
                <li key={i} className={`relative flex gap-3 transition-all duration-500 ${visible ? 'translate-y-0 opacity-100' : 'pointer-events-none translate-y-2 opacity-0'}`}>
                  <span className={`relative z-10 mt-0.5 flex h-[31px] w-[31px] shrink-0 items-center justify-center rounded-full border ${st.kind === 'sink' || st.kind === 'impact' ? 'border-risk-critical/50 bg-risk-critical/15 text-[#ff8a95]' : st.kind === 'request' ? 'border-lime/40 bg-lime/10 text-lime' : 'border-white/15 bg-ink-850 text-fog-300'} ${current ? 'shadow-glow-red' : ''}`}>
                    <Icon size={14} />
                    {current && <span className="absolute inset-0 animate-pulse-ring rounded-full border border-risk-critical/60" />}
                  </span>
                  <div className={`min-w-0 flex-1 rounded-xl border px-4 py-3 ${st.kind === 'sink' ? 'border-risk-critical/30 bg-risk-critical/[0.05]' : 'border-white/[0.07] bg-white/[0.02]'}`}>
                    <div className="text-sm text-fog-50">{st.kind === 'hop' ? st.title.replace(st.name, prettyFn(st.name)) : st.title}</div>
                    {st.detail && <div className="mt-1 text-xs leading-relaxed text-fog-400">{st.detail}</div>}
                    {st.file_path && st.kind === 'hop' && <div className="mt-1 truncate font-mono text-[11px] text-fog-500">{st.file_path}{st.line ? `:${st.line}` : ''}</div>}
                    {st.value && <div className="mt-2 truncate rounded-md bg-ink-950/70 px-2 py-1 font-mono text-[11px] text-[#ff8a95]">{st.value}</div>}
                    {st.code && <div className="mt-2 overflow-x-auto rounded-md bg-ink-950/70 px-2 py-1.5 font-mono text-[11px] text-fog-200"><span className="mr-2 text-fog-600">{st.line}</span>{st.code}</div>}
                    {stopHere && attack.verdict === 'blocked' && <div className="mt-2 text-xs text-fog-500">In reality the request stops before this point: {attack.verdict_text.toLowerCase()}</div>}
                  </div>
                </li>
              )
            })}
          </ol>
        </div>
      </div>
    </Card>
  )
}
