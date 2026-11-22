import { useMemo, useState } from 'react'
import { Link, useNavigate, useParams, useSearchParams } from 'react-router-dom'
import {
  ArrowUpRight, Check, ChevronRight, Crosshair, Download, Filter, GitBranch, Network, Radar, RefreshCw,
  Search, ShieldAlert, Timer, Waypoints,
} from 'lucide-react'
import {
  Card, EmptyState, ErrorState, InfoHint, Label, PageHeader, Pill, ProgressBar, ReachBadge, RiskBadge, RiskRing,
  SegmentBar, Skeleton, Spinner, StatTile, TaintBadge, useAsync,
} from '../components/ui'
import { StatusDot } from './Dashboard'
import { api } from '../lib/api'
import { RISK, RISK_ORDER, cweName, duration, prettyFn, timeAgo } from '../lib/format'

const PIPELINE = [
  { at: 5, label: 'Unpack' },
  { at: 20, label: 'Parse & call graph' },
  { at: 55, label: 'AI scoring' },
  { at: 82, label: 'Prioritize' },
  { at: 92, label: 'Save' },
]

function Running({ scan }) {
  return (
    <Card className="relative overflow-hidden p-8 md:p-12">
      <div className="pointer-events-none absolute -top-24 left-1/2 h-48 w-2/3 -translate-x-1/2 rounded-full bg-lime/15 blur-3xl" />
      <div className="relative flex flex-col items-center text-center">
        <div className="relative mb-6 flex h-16 w-16 items-center justify-center">
          <span className="absolute inset-0 rounded-full border border-lime/40 animate-pulse-ring" />
          <span className="absolute inset-2 rounded-full border border-lime/30 animate-pulse-ring" style={{ animationDelay: '0.6s' }} />
          <Radar className="text-lime" />
        </div>
        <div className="font-display text-2xl font-light text-fog-50">{scan.stage || 'Queued'}…</div>
        <div className="mt-2 text-sm text-fog-400">This usually takes a few seconds. The page updates automatically.</div>
        <ProgressBar value={scan.progress} className="mt-8 max-w-xl" />
        <div className="mt-6 grid w-full max-w-2xl grid-cols-5 gap-2">
          {PIPELINE.map((p, i) => {
            const done = scan.progress > (PIPELINE[i + 1]?.at ?? 99)
            const active = !done && scan.progress >= p.at
            return (
              <div key={p.label} className="flex flex-col items-center gap-2">
                <span className={`flex h-6 w-6 items-center justify-center rounded-full border text-[10px] ${done ? 'border-lime bg-lime text-ink-950' : active ? 'border-lime text-lime shadow-glow-sm' : 'border-white/15 text-fog-500'}`}>
                  {done ? <Check size={12} /> : i + 1}
                </span>
                <span className={`text-[11px] ${active ? 'text-lime' : done ? 'text-fog-300' : 'text-fog-500'}`}>{p.label}</span>
              </div>
            )
          })}
        </div>
      </div>
    </Card>
  )
}

const CHIP_GROUPS = [
  { key: 'category', label: 'Risk', options: RISK_ORDER.map((c) => [c, c]) },
  { key: 'reachability', label: 'Reach', options: [['reachable', 'Reachable'], ['startup_only', 'Startup only'], ['unreachable', 'Dead code']] },
  { key: 'taint', label: 'Data flow', options: [['user_input', 'User input'], ['parameter', 'Parameter'], ['none', 'None'], ['unknown', 'AI only']] },
]

function FindingRow({ f, rank, scanId }) {
  return (
    <Link to={`/scans/${scanId}/findings/${f.finding_id}`} className="group block animate-fade-up" style={{ animationDelay: `${Math.min(rank, 12) * 30}ms` }}>
      <div className={`flex items-center gap-4 rounded-2xl border px-4 py-4 transition-all duration-200 md:px-5 ${f.reachability_status === 'reachable' && f.taint === 'user_input' ? 'border-risk-critical/20 bg-risk-critical/[0.03] hover:border-risk-critical/45' : 'border-white/[0.06] bg-white/[0.02] hover:border-lime/30'} ${f.reachability_status === 'unreachable' ? 'opacity-70 hover:opacity-100' : ''}`}>
        <span className="hidden w-7 font-mono text-xs text-fog-600 sm:block">#{rank}</span>
        <RiskRing score={f.risk_score} size={50} />
        <div className="min-w-0 flex-1">
          <div className="flex flex-wrap items-center gap-2">
            <span className="truncate font-medium text-fog-50">{f.title || cweName(f.cwe)}</span>
            <span className="font-mono text-[11px] text-fog-500">{f.cwe}</span>
          </div>
          <div className="mt-1 truncate font-mono text-xs text-fog-400">
            <span className="text-fog-200">{prettyFn(f.function_name)}</span> · {f.file_path}:{f.line}
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5 md:hidden">
            <ReachBadge status={f.reachability_status} /><TaintBadge taint={f.taint} />
          </div>
        </div>
        <div className="hidden shrink-0 items-center gap-1.5 md:flex">
          <ReachBadge status={f.reachability_status} />
          <TaintBadge taint={f.taint} />
          <RiskBadge category={f.risk_category} />
        </div>
        <ChevronRight size={16} className="shrink-0 text-fog-600 transition-transform group-hover:translate-x-1 group-hover:text-lime" />
      </div>
    </Link>
  )
}

function ExportMenu({ scanId }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="relative">
      <button className="btn-ghost" onClick={() => setOpen((o) => !o)} onBlur={() => setTimeout(() => setOpen(false), 150)}><Download size={15} /> Export</button>
      {open && (
        <div className="absolute right-0 z-20 mt-2 w-56 overflow-hidden rounded-xl border border-white/10 bg-ink-850/95 p-1 backdrop-blur-xl">
          {[['json', 'JSON report', 'Full results + paths'], ['sarif', 'SARIF 2.1.0', 'GitHub code scanning, IDEs'], ['csv', 'CSV', 'Spreadsheets']].map(([fmt, t, d]) => (
            <a key={fmt} href={api.exportUrl(scanId, fmt)} className="block rounded-lg px-3 py-2.5 hover:bg-white/5">
              <div className="text-sm text-fog-50">{t}</div><div className="text-xs text-fog-500">{d}</div>
            </a>
          ))}
        </div>
      )}
    </div>
  )
}

function EntryPoints({ scanId }) {
  const eps = useAsync(() => api.entryPoints(scanId), [scanId])
  const routes = (eps.data || []).filter((e) => e.kind !== 'startup')
  const startup = (eps.data || []).filter((e) => e.kind === 'startup')
  return (
    <Card className="p-6" data-tour="attack-surface">
      <div className="flex items-center gap-2"><Label>Attack surface</Label><InfoHint title="Attack surface" learn="entry-points" align="right">Routes and request handlers detected in the code — the doors an attacker can knock on. Faded routes are inactive: they are registered in code that never runs.</InfoHint></div>
      <div className="mt-2 text-sm text-fog-400">{routes.filter((r) => r.active).length} active entry points · {startup.length} startup roots</div>
      <div className="mt-5 max-h-80 space-y-2 overflow-auto pr-1">
        {eps.loading && <Skeleton className="h-24" />}
        {routes.map((e, i) => (
          <div key={`${e.node_id}-${i}`} className={`flex items-center gap-3 rounded-lg border border-white/[0.05] px-3 py-2 ${e.active ? '' : 'opacity-50'}`} title={e.active ? 'Registered by code that runs at startup' : 'Registered in code that never runs (dead router / file)'}>
            <span className={`font-mono text-[10px] font-semibold ${e.active ? 'text-lime' : 'text-fog-500'}`}>{(e.label || '').split(' ')[0]}</span>
            <span className="min-w-0 flex-1 truncate font-mono text-xs text-fog-200">{(e.label || '').split(' ').slice(1).join(' ') || e.label}</span>
            {!e.active && <span className="text-[10px] text-fog-500">inactive</span>}
          </div>
        ))}
        {!eps.loading && routes.length === 0 && <div className="text-sm text-fog-500">No request handlers detected — the project is analyzed as a library/module.</div>}
      </div>
    </Card>
  )
}

export default function ScanResults() {
  const { scanId } = useParams()
  const navigate = useNavigate()
  const scan = useAsync(() => api.scan(scanId), [scanId], { poll: 1000, until: (s) => !['queued', 'running'].includes(s.status) })
  const done = scan.data?.status === 'completed'
  const [filters, setFilters] = useState({ category: [], reachability: [], taint: [] })
  const [params] = useSearchParams()
  const [q, setQ] = useState(params.get('q') || '')
  const [sort, setSort] = useState('risk')
  const findings = useAsync(() => (done ? api.findings(scanId, { sort }) : Promise.resolve([])), [scanId, done, sort])

  const visible = useMemo(() => {
    const needle = q.trim().toLowerCase()
    return (findings.data || []).filter((f) =>
      (!filters.category.length || filters.category.includes(f.risk_category)) &&
      (!filters.reachability.length || filters.reachability.includes(f.reachability_status)) &&
      (!filters.taint.length || filters.taint.includes(f.taint)) &&
      (!needle || [f.file_path, f.function_name, f.cwe, f.title, f.rule_message].some((v) => (v || '').toLowerCase().includes(needle))))
  }, [findings.data, filters, q])

  const toggle = (key, val) => setFilters((f) => ({ ...f, [key]: f[key].includes(val) ? f[key].filter((x) => x !== val) : [...f[key], val] }))
  const activeFilters = filters.category.length + filters.reachability.length + filters.taint.length + (q ? 1 : 0)

  if (scan.error && !scan.data) return <ErrorState error={scan.error} onRetry={scan.reload} />
  if (!scan.data) return <div className="space-y-4"><Skeleton className="h-24" /><Skeleton className="h-64" /></div>
  const s = scan.data
  const sum = s.summary || {}

  const rescan = async () => {
    const n = await api.startScan(s.project_id)
    navigate(`/scans/${n.scan_id}`)
  }

  return (
    <div>
      <PageHeader label={`Scan · ${scanId.slice(0, 8)}`} title={s.project_name} fade={done ? `— ${s.finding_count} findings` : ''}>
        <span data-tour="scan-actions" className="flex flex-wrap items-center gap-3">
        <StatusDot status={s.status} />
        {done && <Link to={`/scans/${scanId}/graph`} className="btn-ghost"><Network size={15} /> Call graph</Link>}
        {done && <ExportMenu scanId={scanId} />}
        {['completed', 'failed'].includes(s.status) && <button className="btn-ghost" onClick={rescan}><RefreshCw size={15} /> Rescan</button>}
        </span>
      </PageHeader>
      <div className="mt-3 text-xs text-fog-500">Started {timeAgo(s.created_at)}{done && <> · {duration(s.duration_ms)} · model {sum.model?.display_name} · mode {s.analysis_mode}</>}</div>

      <div className="mt-10">
        {['queued', 'running'].includes(s.status) && <Running scan={s} />}
        {s.status === 'failed' && (
          <EmptyState icon={ShieldAlert} title="Scan failed" action={<button className="btn-ghost" onClick={rescan}><RefreshCw size={14} /> Try again</button>}>
            {s.error_message}
          </EmptyState>
        )}
      </div>

      {done && (
        <>
          <section data-tour="scan-stats" className="grid grid-cols-2 gap-4 lg:grid-cols-4">
            <StatTile label="Actionable" value={sum.actionable ?? 0} sub="reachable · user input proven" icon={Crosshair} tone={sum.actionable ? 'danger' : undefined} />
            <StatTile label="Findings" value={s.finding_count} sub={`${sum.by_taint?.unknown || 0} AI-only suspicions`} icon={ShieldAlert} />
            <StatTile label="Deprioritized" value={`${sum.noise_reduction_pct ?? 0}%`} sub={`${sum.deprioritized ?? 0} in dead / startup-only code`} icon={Radar} accent />
            <StatTile label="Code analyzed" value={sum.functions ?? 0} sub={`functions · ${sum.files_analyzed} files · ${sum.edges} call edges`} icon={GitBranch} />
          </section>

          <section className="mt-6 grid items-start gap-6 lg:grid-cols-[1.7fr_1fr]">
            <Card className="p-6" data-tour="risk-dist">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2"><Label>Risk distribution</Label><InfoHint title="Risk distribution" learn="risk-score">Every finding gets a 0–100 risk score: severity, proof of user input and the AI probability, multiplied by reachability. Click a tile to filter the list.</InfoHint></div>
                <span className="font-mono text-xs text-fog-500">max {Math.round(sum.max_risk || 0)}/100</span>
              </div>
              <div className="mt-5"><SegmentBar segments={RISK_ORDER.map((c) => ({ label: c, value: sum.by_risk_category?.[c] || 0, color: RISK[c].color }))} height={12} /></div>
              <div className="mt-4 grid grid-cols-2 gap-3 sm:grid-cols-4">
                {RISK_ORDER.map((c) => (
                  <button key={c} onClick={() => toggle('category', c)} className={`rounded-xl border p-3 text-left transition ${filters.category.includes(c) ? 'border-lime/40 bg-lime/[0.05]' : 'border-white/[0.06] hover:border-white/20'}`}>
                    <div className="font-display text-2xl font-light tabular-nums" style={{ color: RISK[c].color }}>{sum.by_risk_category?.[c] || 0}</div>
                    <div className="text-xs text-fog-400">{c}</div>
                  </button>
                ))}
              </div>
              <div className="mt-6 grid grid-cols-3 gap-3 border-t border-white/[0.06] pt-5 text-center">
                {[['reachable', 'Reachable', 'text-risk-critical'], ['startup_only', 'Startup only', 'text-risk-high'], ['unreachable', 'Dead code', 'text-fog-400']].map(([k, l, c]) => (
                  <div key={k}><div className={`font-display text-xl tabular-nums ${c}`}>{sum.by_reachability?.[k] || 0}</div><div className="text-[11px] text-fog-500">{l}</div></div>
                ))}
              </div>
            </Card>
            <EntryPoints scanId={scanId} />
          </section>

          <section className="mt-14">
            <div className="flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
              <div>
                <div className="flex items-center gap-2"><Label>Prioritized findings</Label><InfoHint title="Prioritized findings" learn="badges">Sorted by risk: fix from the top. Badges show reachability and whether user input is proven to reach the dangerous call.</InfoHint></div>
                <h2 className="mt-3 font-display text-3xl font-light text-fog-50">Fix these <span className="text-fade">in this order.</span></h2>
              </div>
              <div className="flex items-center gap-2">
                <div className="relative">
                  <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-fog-500" />
                  <input className="input w-60 py-2 pl-9" placeholder="Search file, function, CWE" value={q} onChange={(e) => setQ(e.target.value)} />
                </div>
                <select className="input w-auto py-2" value={sort} onChange={(e) => setSort(e.target.value)} aria-label="Sort">
                  <option value="risk">Sort: risk</option><option value="severity">Sort: severity</option><option value="ai">Sort: AI score</option><option value="file">Sort: file</option>
                </select>
              </div>
            </div>
            <div data-tour="filters" className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-3">
              <Filter size={14} className="text-fog-500" />
              {CHIP_GROUPS.map((g) => (
                <div key={g.key} className="flex flex-wrap items-center gap-1.5">
                  <span className="mr-1 font-mono text-[10px] uppercase tracking-[0.16em] text-fog-500">{g.label}</span>
                  {g.options.map(([v, l]) => (
                    <span key={v} className={`chip ${filters[g.key].includes(v) ? 'chip-active' : ''}`} onClick={() => toggle(g.key, v)}>{l}</span>
                  ))}
                </div>
              ))}
              {activeFilters > 0 && <button className="text-xs text-lime hover:underline" onClick={() => { setFilters({ category: [], reachability: [], taint: [] }); setQ('') }}>Clear ({activeFilters})</button>}
            </div>
            <div data-tour="findings" className="mt-6 flex flex-col gap-2.5">
              {findings.loading && !findings.data && [0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-20" />)}
              {findings.data && visible.length === 0 && (
                <EmptyState icon={Check} title={findings.data.length ? 'Nothing matches these filters' : 'No vulnerabilities found'}>
                  {findings.data.length ? 'Try removing a filter.' : 'No rule matched and the AI model found no high-confidence suspicion.'}
                </EmptyState>
              )}
              {visible.map((f, i) => <FindingRow key={f.finding_id} f={f} rank={i + 1} scanId={scanId} />)}
            </div>
            {visible.length > 0 && (
              <div className="mt-6 flex items-center justify-between text-xs text-fog-500">
                <span>{visible.length} of {findings.data.length} findings</span>
                <span className="flex items-center gap-2"><Waypoints size={13} /> Open a finding to see its attack path</span>
              </div>
            )}
          </section>
        </>
      )}
      {done && s.summary?.parse_errors > 0 && (
        <div className="mt-8"><Pill tone="warn"><Timer size={12} /> {s.summary.parse_errors} file(s) could not be parsed and were skipped</Pill></div>
      )}
      {done && (
        <div className="mt-16 flex justify-center">
          <Link to="/scan/new" className="btn-ghost">Scan another project <ArrowUpRight size={15} /></Link>
        </div>
      )}
    </div>
  )
}
