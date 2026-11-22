import { Fragment } from 'react'
import { DoorOpen, FileCode2, Skull, Waypoints } from 'lucide-react'
import { prettyFn } from '../lib/format'

/**
 * Glowing chain: entry point -> ... -> vulnerable function.
 * steps: [{ id, name, file_path, line, node_type }]
 */
export default function AttackPath({ steps = [], entryLabel, variant = 'attack', emptyText }) {
  if (!steps.length) {
    return (
      <div className="rounded-xl border border-dashed border-white/10 px-5 py-6 text-sm text-fog-400">
        {emptyText || 'No path from any entry point reaches this function.'}
      </div>
    )
  }
  const accent = variant === 'attack' ? '#FF4D5E' : '#B4FF39'
  return (
    <div className="relative">
      <ol className="flex flex-col gap-0 lg:flex-row lg:flex-wrap lg:items-stretch lg:gap-y-4">
        {steps.map((s, i) => {
          const first = i === 0
          const last = i === steps.length - 1
          const Icon = first ? DoorOpen : last ? (variant === 'attack' ? Skull : FileCode2) : s.node_type === 'Module' ? FileCode2 : Waypoints
          return (
            <Fragment key={`${s.id}-${i}`}>
              <li className="animate-fade-up" style={{ animationDelay: `${i * 90}ms` }}>
                <div
                  className={`relative rounded-xl border px-4 py-3 backdrop-blur ${last ? 'bg-risk-critical/[0.07]' : first ? 'bg-lime/[0.06]' : 'bg-white/[0.03]'}`}
                  style={{
                    borderColor: last ? `${accent}66` : first ? 'rgba(180,255,57,0.4)' : 'rgba(255,255,255,0.08)',
                    boxShadow: last ? `0 0 28px -8px ${accent}` : first ? '0 0 24px -10px #B4FF39' : 'none',
                  }}
                >
                  <div className="flex items-center gap-2">
                    <Icon size={14} style={{ color: last ? accent : first ? '#B4FF39' : '#8D958A' }} />
                    <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-fog-500">
                      {first ? (entryLabel || 'Entry point') : last ? (variant === 'attack' ? 'Vulnerable sink' : 'Sink function') : `Step ${i}`}
                    </span>
                  </div>
                  <div className="mt-1.5 max-w-[260px] truncate font-mono text-[13px] text-fog-50" title={s.name}>
                    {s.node_type === 'Module' || s.name === '__top_level__' ? <>{(s.file_path || '').split('/').pop()} <span className="text-fog-500">· module load</span></> : prettyFn(s.name)}
                  </div>
                  <div className="mt-0.5 max-w-[260px] truncate text-[11px] text-fog-500" title={s.file_path}>
                    {s.file_path}{s.line ? `:${s.line}` : ''}
                  </div>
                </div>
              </li>
              {!last && (
                <li aria-hidden className="flex items-center justify-center py-1 lg:px-1 lg:py-0">
                  <svg className="hidden lg:block" width="44" height="14" viewBox="0 0 44 14">
                    <line x1="0" y1="7" x2="36" y2="7" stroke={accent} strokeOpacity="0.7" strokeWidth="1.5" strokeDasharray="4 4" className="animate-dash" />
                    <path d="M34 2l6 5-6 5" fill="none" stroke={accent} strokeWidth="1.5" />
                  </svg>
                  <svg className="lg:hidden" width="14" height="28" viewBox="0 0 14 28">
                    <line x1="7" y1="0" x2="7" y2="22" stroke={accent} strokeOpacity="0.7" strokeWidth="1.5" strokeDasharray="4 4" className="animate-dash" />
                    <path d="M2 20l5 6 5-6" fill="none" stroke={accent} strokeWidth="1.5" />
                  </svg>
                </li>
              )}
            </Fragment>
          )
        })}
      </ol>
    </div>
  )
}
