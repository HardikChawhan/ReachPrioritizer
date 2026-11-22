import { Link } from 'react-router-dom'
import { ArrowRight, ArrowUpRight, Crosshair, FileSearch, GitBranch, Radar, ShieldAlert, Sparkles, Workflow } from 'lucide-react'
import ParticleField from '../components/ParticleField'
import { BarRow, Card, EmptyState, InfoHint, Label, RiskBadge, SegmentBar, Skeleton, StatTile, useAsync } from '../components/ui'
import { api } from '../lib/api'
import { RISK, RISK_ORDER, cweName, duration, timeAgo } from '../lib/format'

const STEPS = [
  { icon: FileSearch, title: 'Parse', text: 'Every JS / TS file is parsed into an AST. Nothing is executed.' },
  { icon: GitBranch, title: 'Call graph', text: 'Calls, callbacks, imports, classes and routers are linked across files.' },
  { icon: Crosshair, title: 'Entry points', text: 'Servers, routes and handlers that attackers can actually hit are detected.' },
  { icon: Workflow, title: 'Taint flow', text: 'User input is followed through functions into dangerous sinks.' },
  { icon: Sparkles, title: 'AI score', text: 'A model trained on 21,896 real JS functions adds a vulnerability probability.' },
  { icon: Radar, title: 'Prioritize', text: 'Severity × exploitability × AI × reachability = one explainable risk score.' },
]

function Hero({ latest }) {
  return (
    <section className="relative -mx-5 mb-16 overflow-hidden rounded-[28px] border border-white/[0.06] bg-ink-900/40 px-6 py-14 md:-mx-8 md:px-14 md:py-20">
      <div className="pointer-events-none absolute left-1/2 top-0 h-72 w-[60%] -translate-x-1/2 bg-lime/20 blur-[120px]" />
      <div className="absolute inset-y-0 right-0 w-full opacity-70 md:w-[62%] md:opacity-100">
        <ParticleField />
      </div>
      <div className="pointer-events-none absolute inset-0 bg-gradient-to-r from-ink-950 via-ink-950/70 to-transparent md:via-ink-950/20" />
      <div className="relative max-w-2xl">
        <Label className="animate-fade-up">Reachability-aware security</Label>
        <h1 className="mt-6 animate-fade-up font-display text-5xl font-light leading-[1.02] tracking-tight text-fog-50 md:text-7xl" style={{ animationDelay: '80ms' }}>
          Find what's <span className="text-lime-grad">actually</span><br />
          <span className="text-fade">exploitable.</span>
        </h1>
        <p className="mt-6 max-w-xl animate-fade-up text-base leading-relaxed text-fog-300 md:text-lg" style={{ animationDelay: '160ms' }}>
          ReachPrioritizer traces every vulnerability back to the route an attacker would use —
          and pushes dead code and startup-only issues to the bottom of the list.
        </p>
        <div className="mt-9 flex animate-fade-up flex-wrap gap-3" style={{ animationDelay: '240ms' }}>
          <Link to="/scan/new" className="btn-primary px-6 py-3">Scan a project <ArrowUpRight size={16} /></Link>
          {latest && <Link to={`/scans/${latest.scan_id}`} className="btn-ghost px-6 py-3">Latest results <ArrowRight size={16} /></Link>}
        </div>
        <div className="mt-12 flex animate-fade-up items-center gap-6 font-mono text-[11px] uppercase tracking-[0.16em] text-fog-500" style={{ animationDelay: '320ms' }}>
          <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-lime shadow-glow-sm" />call graph</span>
          <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full bg-risk-critical shadow-glow-red" />reachable sink</span>
        </div>
      </div>
    </section>
  )
}

function ScanRow({ s }) {
  const sum = s.summary || {}
  const cats = sum.by_risk_category || {}
  return (
    <Link to={`/scans/${s.scan_id}`} className="group block">
      <Card hover className="flex flex-col gap-4 p-5 md:flex-row md:items-center">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-3">
            <span className="truncate font-display text-lg text-fog-50">{s.project_name}</span>
            <StatusDot status={s.status} />
          </div>
          <div className="mt-1 text-xs text-fog-500">{timeAgo(s.created_at)} · {sum.files_analyzed ?? '–'} files · {sum.functions ?? '–'} functions · {duration(s.duration_ms)}</div>
        </div>
        {s.status === 'completed' ? (
          <div className="flex flex-1 flex-col gap-2 md:max-w-sm">
            <SegmentBar segments={RISK_ORDER.map((c) => ({ label: c, value: cats[c] || 0, color: RISK[c].color }))} height={6} />
            <div className="flex justify-between text-[11px] text-fog-400">
              <span><b className="font-medium text-risk-critical">{sum.actionable ?? 0}</b> actionable</span>
              <span>{s.finding_count} findings</span>
              <span>{sum.noise_reduction_pct ?? 0}% deprioritized</span>
            </div>
          </div>
        ) : (
          <div className="text-xs text-fog-400 md:max-w-sm">{s.status === 'failed' ? s.error_message : s.stage}</div>
        )}
        <ArrowRight size={16} className="hidden text-fog-500 transition-transform group-hover:translate-x-1 group-hover:text-lime md:block" />
      </Card>
    </Link>
  )
}

export function StatusDot({ status }) {
  const map = {
    completed: ['bg-lime', 'Completed'], running: ['bg-risk-medium animate-pulse', 'Running'],
    queued: ['bg-fog-400 animate-pulse', 'Queued'], failed: ['bg-risk-critical', 'Failed'],
  }
  const [cls, label] = map[status] || ['bg-fog-500', status]
  return (
    <span className="inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-fog-400">
      <span className={`h-1.5 w-1.5 rounded-full ${cls}`} />{label}
    </span>
  )
}

export default function Dashboard() {
  const scans = useAsync(() => api.scans(), [], { poll: 4000, until: (d) => !d.some((s) => ['queued', 'running'].includes(s.status)) })
  const running = (scans.data || []).filter((s) => ['queued', 'running'].includes(s.status)).length
  const stats = useAsync(() => api.stats(), [running])
  const list = scans.data || []
  const latest = list.find((s) => s.status === 'completed')
  const st = stats.data || {}
  const latestIds = new Set(st.latest_scan_ids || [])
  const completedLatest = list.filter((s) => latestIds.has(s.scan_id))
  const cats = st.by_risk_category || {}
  const reach = st.by_reachability || {}
  const totalFindings = Object.values(cats).reduce((a, b) => a + b, 0)
  const actionable = completedLatest.reduce((a, s) => a + ((s.summary && s.summary.actionable) || 0), 0)
  const cwes = Object.entries(st.top_cwes || {})
  const maxCwe = Math.max(1, ...cwes.map(([, v]) => v))

  return (
    <div>
      <Hero latest={latest} />

      <section data-tour="stats" className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {stats.loading && !stats.data ? [0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-32" />) : (<>
          <StatTile label="Projects" value={st.totals?.projects ?? 0} sub={`${st.totals?.completed_scans ?? 0} completed scans`} icon={FileSearch} />
          <StatTile label="Findings (latest)" value={totalFindings} sub="across each project's latest scan" icon={ShieldAlert} />
          <StatTile label="Actionable" value={actionable} sub="reachable + user input proven" icon={Crosshair} tone={actionable ? 'danger' : undefined} />
          <StatTile label="Deprioritized" value={(reach.unreachable || 0) + (reach.startup_only || 0)} sub="dead code or startup-only" icon={Radar} accent />
        </>)}
      </section>

      <section className="mt-16 grid gap-8 lg:grid-cols-[1.6fr_1fr]">
        <div data-tour="recent-scans">
          <div className="mb-5 flex items-end justify-between">
            <div>
              <Label>Recent scans</Label>
              <h2 className="mt-3 font-display text-3xl font-light text-fog-50">Your projects</h2>
            </div>
            <Link to="/scans" className="text-sm text-fog-400 hover:text-lime">View all →</Link>
          </div>
          <div className="flex flex-col gap-3">
            {scans.loading && !scans.data && [0, 1, 2].map((i) => <Skeleton key={i} className="h-20" />)}
            {!scans.loading && list.length === 0 && (
              <EmptyState icon={FileSearch} title="No scans yet" action={<Link className="btn-primary" to="/scan/new">Scan your first project</Link>}>
                Upload a ZIP of any Node.js / JavaScript / TypeScript project. Try one of the bundled apps in <span className="font-mono text-fog-300">test-applications/</span>.
              </EmptyState>
            )}
            {list.slice(0, 6).map((s) => <ScanRow key={s.scan_id} s={s} />)}
          </div>
        </div>
        <div data-tour="insights" className="flex flex-col gap-6">
          <Card className="p-6">
            <div className="flex items-center gap-2"><Label>Risk mix</Label><InfoHint title="Risk mix" learn="risk-score" align="right">How all findings in each project's latest scan split by risk category. The category comes from the 0–100 risk score.</InfoHint></div>
            <div className="mt-5 space-y-4">
              {RISK_ORDER.map((c) => <BarRow key={c} label={<span className="flex items-center gap-2"><RiskBadge category={c} /></span>} value={cats[c] || 0} max={Math.max(1, totalFindings)} color={RISK[c].color} />)}
            </div>
          </Card>
          <Card className="p-6">
            <div className="flex items-center gap-2"><Label>Top weaknesses</Label><InfoHint title="Top weaknesses" learn="vulnerabilities" align="right">The most frequent vulnerability types (CWE ids) across your latest scans.</InfoHint></div>
            <div className="mt-5 space-y-4">
              {cwes.length === 0 && <div className="text-sm text-fog-500">No findings yet.</div>}
              {cwes.map(([cwe, n]) => <BarRow key={cwe} label={`${cweName(cwe)} · ${cwe}`} value={n} max={maxCwe} />)}
            </div>
          </Card>
        </div>
      </section>

      <section className="mt-24">
        <Label>How it works</Label>
        <h2 className="mt-4 max-w-3xl font-display text-4xl font-light leading-tight text-fog-50">
          Six stages from source code <span className="text-fade">to the one bug you fix first.</span>
        </h2>
        <div className="mt-10 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {STEPS.map((s, i) => (
            <Card key={s.title} hover className="group relative overflow-hidden p-6">
              <div className="absolute right-5 top-5 font-mono text-xs text-fog-600">0{i + 1}</div>
              <div className="mb-5 inline-flex rounded-xl border border-lime/20 bg-lime/[0.06] p-3 text-lime transition-shadow group-hover:shadow-glow-sm"><s.icon size={18} /></div>
              <div className="font-display text-xl text-fog-50">{s.title}</div>
              <p className="mt-2 text-sm leading-relaxed text-fog-400">{s.text}</p>
            </Card>
          ))}
        </div>
      </section>
    </div>
  )
}
