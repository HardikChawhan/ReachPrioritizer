import { useEffect, useMemo, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import {
  ArrowDownRight, ArrowLeft, ArrowRight, ArrowRightLeft, ArrowUpRight, CircleCheck, CircleDot, CirclePlus, Equal,
  GitCompareArrows, Minus, Route, Waypoints,
} from 'lucide-react'
import AttackPath from '../components/AttackPath'
import DiffGraph, { DIFF_COLORS } from '../components/DiffGraph'
import { Card, EmptyState, ErrorState, InfoHint, Label, Pill, RiskRing, Skeleton, useAsync } from '../components/ui'
import { api } from '../lib/api'
import { prettyFn, timeAgo } from '../lib/format'

const KIND = {
  fixed: { label: 'Fixed', icon: CircleCheck, color: DIFF_COLORS.fixed, text: 'text-lime', border: 'border-lime/30', bg: 'bg-lime/[0.05]', hint: 'In the old scan, gone now' },
  new: { label: 'New', icon: CirclePlus, color: DIFF_COLORS.new, text: 'text-[#ff8a95]', border: 'border-risk-critical/30', bg: 'bg-risk-critical/[0.05]', hint: 'Appeared in the new scan' },
  open: { label: 'Still open', icon: CircleDot, color: DIFF_COLORS.open, text: 'text-[#ffb27a]', border: 'border-risk-high/25', bg: 'bg-risk-high/[0.04]', hint: 'In both scans' },
}

function scanLabel(s) {
  if (!s) return '…'
  return `${s.source_ref || s.scan_id.slice(0, 8)} · ${timeAgo(s.created_at)}`
}

function Trend({ points, baseId, headId }) {
  if (!points || points.length < 2) return <div className="flex h-36 items-center justify-center text-xs text-fog-500">Scan the project again to see a trend.</div>
  const W = 640; const H = 150; const P = 28
  const max = Math.max(1, ...points.map((p) => p.findings))
  const x = (i) => P + (i * (W - 2 * P)) / (points.length - 1)
  const y = (v) => H - P - (v / max) * (H - 2 * P)
  const line = (key) => points.map((p, i) => `${i ? 'L' : 'M'}${x(i)},${y(p[key])}`).join(' ')
  const series = [['findings', '#E3E7E0', 'All findings'], ['actionable', '#FF4D5E', 'Actionable'], ['critical', '#FF9442', 'Critical']]
  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="h-40 w-full" role="img" aria-label="Findings over time">
        {[0, 0.5, 1].map((t) => <line key={t} x1={P} x2={W - P} y1={y(max * t)} y2={y(max * t)} stroke="rgba(255,255,255,0.05)" />)}
        {series.map(([k, c]) => <path key={k} d={line(k)} fill="none" stroke={c} strokeWidth="2" strokeLinejoin="round" style={{ filter: `drop-shadow(0 0 6px ${c}66)` }} />)}
        {points.map((p, i) => {
          const mark = p.scan_id === baseId ? 'before' : p.scan_id === headId ? 'after' : null
          return (
            <g key={p.scan_id}>
              {series.map(([k, c]) => <circle key={k} cx={x(i)} cy={y(p[k])} r={mark ? 4 : 2.5} fill={c} />)}
              {mark && <text x={x(i)} y={H - 6} textAnchor="middle" fontSize="10" fill={mark === 'after' ? '#B4FF39' : '#8D958A'} fontFamily="JetBrains Mono Variable, monospace">{mark}</text>}
              <title>{`${p.source_ref || ''} — ${p.findings} findings, ${p.actionable} actionable, ${p.critical} critical`}</title>
            </g>
          )
        })}
      </svg>
      <div className="mt-1 flex flex-wrap gap-4 text-[11px] text-fog-400">
        {series.map(([k, c, l]) => <span key={k} className="flex items-center gap-1.5"><span className="h-0.5 w-4 rounded" style={{ background: c }} />{l}</span>)}
      </div>
    </div>
  )
}

function Delta({ before, after, invert = false, suffix = '' }) {
  const d = Math.round((after - before) * 10) / 10
  const good = invert ? d > 0 : d < 0
  const Icon = d === 0 ? Equal : d > 0 ? ArrowUpRight : ArrowDownRight
  return (
    <span className={`inline-flex items-center gap-1 font-mono text-xs ${d === 0 ? 'text-fog-500' : good ? 'text-lime' : 'text-[#ff8a95]'}`}>
      <Icon size={13} />{d > 0 ? '+' : ''}{d}{suffix}
    </span>
  )
}

function ItemRow({ item, kind, selected, onClick }) {
  const k = KIND[kind]
  const f = kind === 'open' ? item.head : item
  return (
    <button type="button" onClick={onClick}
      className={`flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition ${selected ? `${k.border} ${k.bg}` : 'border-white/[0.06] bg-white/[0.02] hover:border-white/20'}`}>
      <RiskRing score={f.risk_score} size={36} stroke={4} />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm text-fog-50">{f.title}</span>
        <span className="block truncate font-mono text-[11px] text-fog-500">
          {f.dependency ? `${f.dependency.package}@${f.dependency.version}` : prettyFn(f.function_name)} · {f.cwe}
        </span>
      </span>
      {kind === 'open' && item.trend !== 'same' && (
        <span className={`font-mono text-[11px] ${item.trend === 'worse' ? 'text-[#ff8a95]' : 'text-lime'}`}>{item.risk_delta > 0 ? '+' : ''}{item.risk_delta}</span>
      )}
      <k.icon size={15} style={{ color: k.color }} />
    </button>
  )
}

function toSteps(ids, nodes) {
  return (ids || []).map((id) => {
    const n = nodes.get(id)
    const [file, name] = id.split('::')
    return { id, name: n?.name || name || id, file_path: n?.file_path || file, line: n?.line, node_type: n?.node_type || (name === '__top_level__' ? 'Module' : 'Function') }
  })
}

export default function Compare() {
  const [params, setParams] = useSearchParams()
  const navigate = useNavigate()
  const baseId = params.get('base')
  const headId = params.get('head')
  const headScan = useAsync(() => (headId ? api.scan(headId) : Promise.resolve(null)), [headId])
  const projectId = headScan.data?.project_id
  const scans = useAsync(() => (projectId ? api.scans(projectId) : Promise.resolve([])), [projectId])
  const trend = useAsync(() => (projectId ? api.trend(projectId) : Promise.resolve(null)), [projectId])
  const cmp = useAsync(() => (baseId && headId ? api.compare(baseId, headId) : Promise.resolve(null)), [baseId, headId])
  const gBase = useAsync(() => (baseId ? api.graph(baseId, 'findings', true) : Promise.resolve(null)), [baseId])
  const gHead = useAsync(() => (headId ? api.graph(headId, 'findings', true) : Promise.resolve(null)), [headId])
  const [tab, setTab] = useState('fixed')
  const [sel, setSel] = useState(null) // { kind, index }

  const completed = (scans.data || []).filter((s) => s.status === 'completed')
  const c = cmp.data

  // only ?head= given: compare with the scan just before it
  useEffect(() => {
    if (baseId || !headScan.data || !scans.data) return
    const older = completed.find((s) => s.scan_id !== headId && s.created_at < headScan.data.created_at)
    if (older) setParams({ base: older.scan_id, head: headId }, { replace: true })
  }, [baseId, headId, headScan.data, scans.data]) // eslint-disable-line react-hooks/exhaustive-deps

  // pick a sensible first tab / selection when data arrives
  useEffect(() => {
    if (!c) return
    const first = c.fixed.length ? 'fixed' : c.new.length ? 'new' : 'open'
    setTab(first)
    setSel(null)
  }, [c])

  const nodesBase = useMemo(() => new Map((gBase.data?.nodes || []).map((n) => [n.node_id, n])), [gBase.data])
  const nodesHead = useMemo(() => new Map((gHead.data?.nodes || []).map((n) => [n.node_id, n])), [gHead.data])

  const lists = c ? { fixed: c.fixed, new: c.new, open: c.still_open } : { fixed: [], new: [], open: [] }
  const current = sel ? lists[sel.kind]?.[sel.index] : null
  const basePath = current ? (sel.kind === 'open' ? current.base.call_path : sel.kind === 'fixed' ? current.call_path : []) : []
  const headPath = current ? (sel.kind === 'open' ? current.head.call_path : sel.kind === 'new' ? current.call_path : []) : []
  const baseFn = current ? (sel.kind === 'open' ? current.base.function_id : sel.kind === 'fixed' ? current.function_id : null) : null
  const headFn = current ? (sel.kind === 'open' ? current.head.function_id : sel.kind === 'new' ? current.function_id : null) : null

  const selectNode = (id) => {
    if (!id) { setSel(null); return }
    for (const kind of ['new', 'fixed', 'open']) {
      const i = lists[kind].findIndex((x) => (kind === 'open' ? x.head.function_id === id || x.base.function_id === id : x.function_id === id))
      if (i >= 0) { setTab(kind); setSel({ kind, index: i }); return }
    }
  }

  const setPair = (b, h) => setParams({ base: b, head: h })

  if (!headId) {
    return (
      <EmptyState icon={GitCompareArrows} title="Pick two scans to compare" action={<Link to="/scans" className="btn-primary">Go to scans</Link>}>
        Open a scan and click “Compare with previous”, or scan a new version of a project first.
      </EmptyState>
    )
  }
  if (cmp.error) return <ErrorState error={cmp.error} onRetry={cmp.reload} />

  const sb = c?.summary.base; const sh = c?.summary.head

  return (
    <div>
      <Link to={`/scans/${headId}`} className="inline-flex items-center gap-2 text-sm text-fog-400 hover:text-lime"><ArrowLeft size={15} /> Back to scan</Link>
      <header className="mt-6 flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
        <div>
          <Label>Compare scans</Label>
          <h1 className="mt-4 font-display text-4xl font-light leading-tight tracking-tight text-fog-50 md:text-5xl">
            {headScan.data?.project_name || '…'} <span className="text-fade">— what changed?</span>
          </h1>
        </div>
        <div data-tour="compare-pickers" className="glass flex flex-wrap items-center gap-2 p-2">
          <select className="input w-64 py-2" value={baseId || ''} onChange={(e) => setPair(e.target.value, headId)} aria-label="Before">
            {!baseId && <option value="">Before…</option>}
            {completed.map((s) => <option key={s.scan_id} value={s.scan_id} disabled={s.scan_id === headId}>Before: {scanLabel(s)}</option>)}
          </select>
          <button type="button" className="rounded-lg p-2 text-fog-400 hover:bg-white/5 hover:text-lime" onClick={() => baseId && setPair(headId, baseId)} title="Swap" aria-label="Swap"><ArrowRightLeft size={15} /></button>
          <select className="input w-64 py-2" value={headId} onChange={(e) => setPair(baseId, e.target.value)} aria-label="After">
            {completed.map((s) => <option key={s.scan_id} value={s.scan_id} disabled={s.scan_id === baseId}>After: {scanLabel(s)}</option>)}
          </select>
        </div>
      </header>
      {c && !c.same_project && <div className="mt-4"><Pill tone="warn">These scans belong to different projects — matching is by file and function name.</Pill></div>}

      {!c ? (
        <div className="mt-10 grid gap-4 md:grid-cols-4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} className="h-28" />)}</div>
      ) : (
        <>
          <section data-tour="compare-summary" className="mt-10 grid grid-cols-2 gap-4 lg:grid-cols-5">
            {[['fixed', c.summary.fixed], ['new', c.summary.new], ['open', c.summary.still_open]].map(([k, v]) => {
              const K = KIND[k]
              return (
                <button key={k} type="button" onClick={() => { setTab(k); setSel(null) }} className={`glass p-5 text-left transition ${tab === k ? `${K.border}` : ''}`}>
                  <div className="flex items-center justify-between"><span className="font-mono text-[11px] uppercase tracking-[0.18em] text-fog-400">{K.label}</span><K.icon size={16} style={{ color: K.color }} /></div>
                  <div className={`mt-3 font-display text-4xl font-light tabular-nums ${K.text}`}>{v}</div>
                  <div className="mt-1 text-xs text-fog-500">{k === 'open' ? `${c.summary.worse} worse · ${c.summary.better} better` : K.hint}</div>
                </button>
              )
            })}
            <Card className="p-5">
              <div className="font-mono text-[11px] uppercase tracking-[0.18em] text-fog-400">Actionable</div>
              <div className="mt-3 flex items-baseline gap-2 font-display text-4xl font-light tabular-nums text-fog-50">{sb.actionable}<ArrowRight size={18} className="text-fog-600" />{sh.actionable}</div>
              <div className="mt-1"><Delta before={sb.actionable} after={sh.actionable} /></div>
            </Card>
            <Card className="p-5">
              <div className="flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.18em] text-fog-400">Total risk <InfoHint title="Total risk" align="right">Sum of the risk scores of all findings. Lower is better.</InfoHint></div>
              <div className="mt-3 flex items-baseline gap-2 font-display text-4xl font-light tabular-nums text-fog-50">{Math.round(sh.risk_sum)}</div>
              <div className="mt-1 flex items-center gap-2 text-xs text-fog-500">was {Math.round(sb.risk_sum)} <Delta before={sb.risk_sum} after={sh.risk_sum} /></div>
            </Card>
          </section>

          {/* side-by-side call graphs */}
          <section data-tour="compare-graphs" className="mt-6">
            <div className="mb-3 flex flex-wrap items-center gap-x-5 gap-y-2">
              <div className="flex items-center gap-2"><Label>Call graphs side by side</Label><InfoHint title="Side-by-side call graphs" learn="compare">Left: the old scan, right: the new one. Only functions on attack paths are drawn. Click a finding or a coloured dot to light up its attack path in both versions.</InfoHint></div>
              <span className="flex flex-wrap gap-4 text-[11px] text-fog-400">
                {[['fixed', 'Fixed'], ['new', 'New'], ['open', 'Still open'], ['added', 'New function'], ['removed', 'Removed function']].map(([k, l]) => (
                  <span key={k} className="flex items-center gap-1.5"><span className="h-2.5 w-2.5 rounded-full" style={{ background: DIFF_COLORS[k], boxShadow: `0 0 8px ${DIFF_COLORS[k]}` }} />{l}</span>
                ))}
              </span>
            </div>
            <div className="grid gap-4 lg:grid-cols-2">
              {[['Before', c.base, gBase.data, c.graph.base_node_status, basePath, baseFn, '#8D958A'], ['After', c.head, gHead.data, c.graph.head_node_status, headPath, headFn, '#B4FF39']].map(([title, meta, g, st, path, fn, accent]) => (
                <Card key={title} className="relative h-[420px] overflow-hidden">
                  <div className="pointer-events-none absolute left-4 top-3 z-10">
                    <div className="font-mono text-[11px] uppercase tracking-[0.18em]" style={{ color: accent }}>{title}</div>
                    <div className="font-mono text-[11px] text-fog-500">{meta.source_ref || meta.scan_id.slice(0, 8)} · {timeAgo(meta.created_at)}</div>
                  </div>
                  {current && path.length === 0 && (
                    <div className="pointer-events-none absolute inset-x-0 bottom-3 z-10 mx-auto w-fit rounded-full border border-white/10 bg-ink-900/90 px-3 py-1 text-[11px] text-fog-400">
                      {title === 'After' && sel?.kind === 'fixed' ? 'Gone in this version ✓' : title === 'Before' && sel?.kind === 'new' ? 'Did not exist before' : 'Not reachable from an entry point'}
                    </div>
                  )}
                  {g ? <DiffGraph graph={g} status={st} path={path} selectedId={fn} onSelect={selectNode} accent={title === 'After' && sel?.kind === 'new' ? '#FF4D5E' : accent} />
                    : <Skeleton className="m-4 h-[380px]" />}
                </Card>
              ))}
            </div>
          </section>

          <section className="mt-6 grid items-start gap-6 lg:grid-cols-[1fr_1.4fr]">
            <Card className="p-4">
              <div className="flex gap-1 rounded-full border border-white/10 bg-ink-900/70 p-1">
                {['fixed', 'new', 'open'].map((k) => (
                  <button key={k} type="button" onClick={() => { setTab(k); setSel(null) }}
                    className={`flex-1 rounded-full px-3 py-1.5 text-xs transition ${tab === k ? 'bg-white/10 text-fog-50' : 'text-fog-400 hover:text-fog-200'}`}>
                    {KIND[k].label} <span className="font-mono text-fog-500">{lists[k].length}</span>
                  </button>
                ))}
              </div>
              <div className="mt-3 max-h-[460px] space-y-2 overflow-auto pr-1">
                {lists[tab].length === 0 && <div className="px-2 py-6 text-center text-sm text-fog-500">{tab === 'fixed' ? 'Nothing was fixed between these scans.' : tab === 'new' ? 'No new findings.' : 'No findings in both scans.'}</div>}
                {lists[tab].map((item, i) => (
                  <ItemRow key={i} item={item} kind={tab} selected={sel?.kind === tab && sel.index === i} onClick={() => setSel({ kind: tab, index: i })} />
                ))}
              </div>
            </Card>

            <div className="flex flex-col gap-6">
              <Card data-tour="compare-paths" className="p-6">
                <div className="flex items-center gap-2"><Route size={16} className="text-risk-critical" /><Label>Attack path: before vs after</Label></div>
                {!current ? (
                  <p className="mt-4 text-sm text-fog-400">Select a finding on the left (or a coloured dot in a graph) to compare its attack path in both versions.</p>
                ) : (
                  <>
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <Pill tone={sel.kind === 'new' ? 'danger' : sel.kind === 'fixed' ? 'lime' : 'warn'} dot>{KIND[sel.kind].label}</Pill>
                      <span className="text-sm text-fog-50">{(sel.kind === 'open' ? current.head : current).title}</span>
                      {sel.kind === 'open' && current.notes.map((n) => <Pill key={n}>{n}</Pill>)}
                    </div>
                    {[['Before', basePath, nodesBase, sel.kind === 'new' ? 'This finding did not exist in the old scan.' : 'No entry point reached this function.'],
                      ['After', headPath, nodesHead, sel.kind === 'fixed' ? 'Fixed — this finding is gone in the new scan.' : 'No entry point reaches this function.']].map(([t, ids, nodes, empty]) => (
                      <div key={t} className="mt-5">
                        <div className="mb-2 flex items-center gap-2 font-mono text-[11px] uppercase tracking-[0.16em] text-fog-500"><Waypoints size={12} />{t}</div>
                        {ids.length ? <AttackPath steps={toSteps(ids, nodes)} variant="attack" entryLabel={ids[0]?.endsWith('__top_level__') ? 'App starts here' : 'Entry point'} />
                          : <div className={`rounded-xl border border-dashed px-4 py-4 text-sm ${t === 'After' && sel.kind === 'fixed' ? 'border-lime/30 text-lime' : 'border-white/10 text-fog-500'}`}>{empty}</div>}
                      </div>
                    ))}
                    <div className="mt-5 flex flex-wrap gap-2">
                      {sel.kind !== 'new' && <Link className="btn-ghost" to={`/scans/${baseId}/findings/${(sel.kind === 'open' ? current.base : current).finding_id}`}>Open in old scan</Link>}
                      {sel.kind !== 'fixed' && <Link className="btn-ghost" to={`/scans/${headId}/findings/${(sel.kind === 'open' ? current.head : current).finding_id}`}>Open in new scan</Link>}
                    </div>
                  </>
                )}
              </Card>

              <Card className="p-6">
                <div className="flex items-center gap-2"><Label>Project trend</Label></div>
                <div className="mt-4"><Trend points={trend.data?.points} baseId={baseId} headId={headId} /></div>
              </Card>

              <Card className="p-6">
                <Label>Attack surface changes</Label>
                <div className="mt-4 grid grid-cols-2 gap-3 text-center sm:grid-cols-4">
                  {[[c.graph.functions_added, '+', 'functions added'], [c.graph.functions_removed, '−', 'functions removed'], [c.graph.routes_added.length, '+', 'routes added'], [c.graph.routes_removed.length, '−', 'routes removed']].map(([n, sign, l]) => [n ? `${sign}${n}` : '0', l]).map(([v, l]) => (
                    <div key={l}><div className="font-display text-2xl text-fog-50">{v}</div><div className="text-[10px] text-fog-500">{l}</div></div>
                  ))}
                </div>
                <div className="mt-4 space-y-1.5">
                  {c.graph.routes_added.map((r) => <div key={r} className="flex items-center gap-2 font-mono text-xs text-[#ff8a95]"><CirclePlus size={12} /> {r}</div>)}
                  {c.graph.routes_removed.map((r) => <div key={r} className="flex items-center gap-2 font-mono text-xs text-lime"><Minus size={12} /> {r}</div>)}
                  {c.graph.reachability_changes.slice(0, 8).map((r) => (
                    <div key={r.node_id} className="flex items-center gap-2 text-xs text-fog-300">
                      <span className={r.direction === 'exposed' ? 'text-[#ff8a95]' : 'text-lime'}>{r.direction === 'exposed' ? 'now exposed' : 'now hidden'}</span>
                      <span className="truncate font-mono">{prettyFn(r.name)}</span>
                      <span className="text-fog-600">{r.from} → {r.to}</span>
                    </div>
                  ))}
                  {!c.graph.routes_added.length && !c.graph.routes_removed.length && !c.graph.reachability_changes.length && <div className="text-xs text-fog-500">No routes or reachability changed.</div>}
                </div>
              </Card>
            </div>
          </section>

          <div className="mt-10 flex justify-center gap-3">
            <button className="btn-ghost" onClick={() => navigate(`/scan/new?project=${projectId}`)}>Scan a newer version</button>
          </div>
        </>
      )}
    </div>
  )
}
