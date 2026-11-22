import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import ForceGraph2D from 'react-force-graph-2d'
import { ArrowLeft, Crosshair, Layers, Maximize2, Search, X } from 'lucide-react'
import { ErrorState, InfoHint, Label, ReachBadge, Spinner, useAsync } from '../components/ui'
import { api } from '../lib/api'
import { pct, prettyFn } from '../lib/format'

const COLORS = {
  entry: '#B4FF39',
  vulnReach: '#FF4D5E',
  vulnDead: '#8a3a44',
  reachable: '#E3E7E0',
  startup: '#8D958A',
  dead: '#394039',
  module: '#5d6b5a',
}

function nodeColor(n) {
  if (n.finding_count > 0) return n.reachability === 'reachable' ? COLORS.vulnReach : COLORS.vulnDead
  if (n.entry_kind) return COLORS.entry
  if (n.node_type === 'Module') return COLORS.module
  if (n.reachability === 'reachable') return COLORS.reachable
  if (n.reachability === 'startup_only') return COLORS.startup
  return COLORS.dead
}

function useSize(ref) {
  const [size, setSize] = useState({ w: 800, h: 600 })
  useEffect(() => {
    if (!ref.current) return undefined
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }))
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [ref])
  return size
}

export default function CallGraph() {
  const { scanId } = useParams()
  const [params] = useSearchParams()
  const target = params.get('focus')
  const [focus, setFocus] = useState(target ? 'all' : 'all')
  const [modules, setModules] = useState(true)
  const [selected, setSelected] = useState(null)
  const [hover, setHover] = useState(null)
  const [query, setQuery] = useState('')
  const fg = useRef(null)
  const box = useRef(null)
  const size = useSize(box)
  const { data, error, loading, reload } = useAsync(() => api.graph(scanId, focus, modules), [scanId, focus, modules])
  const scan = useAsync(() => api.scan(scanId), [scanId])

  const graph = useMemo(() => {
    if (!data) return { nodes: [], links: [] }
    const nodes = data.nodes.map((n) => ({ ...n, id: n.node_id }))
    const ids = new Set(nodes.map((n) => n.id))
    const links = data.edges.filter((e) => ids.has(e.caller_id) && ids.has(e.callee_id)).map((e) => ({ source: e.caller_id, target: e.callee_id, kind: e.kind }))
    return { nodes, links }
  }, [data])

  // adjacency for path highlighting (entry -> selected)
  const { pathNodes, pathLinks } = useMemo(() => {
    const pn = new Set(); const pl = new Set()
    if (!selected || !data) return { pathNodes: pn, pathLinks: pl }
    const adj = new Map()
    for (const e of data.edges) { if (!adj.has(e.caller_id)) adj.set(e.caller_id, []); adj.get(e.caller_id).push(e.callee_id) }
    const roots = data.nodes.filter((n) => n.entry_kind).map((n) => n.node_id)
    const prev = new Map(roots.map((r) => [r, null]))
    const q = [...roots]
    for (let i = 0; i < q.length; i++) {
      if (q[i] === selected.id) break
      for (const m of adj.get(q[i]) || []) if (!prev.has(m)) { prev.set(m, q[i]); q.push(m) }
    }
    if (prev.has(selected.id)) {
      let cur = selected.id
      while (cur != null) { pn.add(cur); const p = prev.get(cur); if (p != null) pl.add(`${p}->${cur}`); cur = p }
    } else pn.add(selected.id)
    return { pathNodes: pn, pathLinks: pl }
  }, [selected, data])

  const focusNode = useCallback((n) => {
    setSelected(n)
    if (n && fg.current && n.x != null) {
      fg.current.centerAt(n.x, n.y, 700)
      fg.current.zoom(3, 700)
    }
  }, [])

  // keep disconnected components close together and readable
  useEffect(() => {
    const g = fg.current
    if (!g || !graph.nodes.length) return
    g.d3Force('charge')?.strength(-150).distanceMax(260)
    g.d3Force('link')?.distance((l) => (l.kind === 'import' ? 70 : 52))
    // gentle gravity so isolated (dead-code) islands stay on screen
    const nodes = graph.nodes
    g.d3Force('gravity', (alpha) => {
      for (const n of nodes) { n.vx -= (n.x || 0) * 0.05 * alpha; n.vy -= (n.y || 0) * 0.05 * alpha }
    })
    g.d3ReheatSimulation?.()
  }, [graph])

  // deep link from a finding: ?focus=<function id>
  useEffect(() => {
    if (!target || !graph.nodes.length) return undefined
    const n = graph.nodes.find((x) => x.id === target)
    if (!n) return undefined
    const t = setTimeout(() => focusNode(n), 900)
    return () => clearTimeout(t)
  }, [target, graph.nodes, focusNode])

  const matches = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return []
    return graph.nodes.filter((n) => (n.name || '').toLowerCase().includes(q) || (n.file_path || '').toLowerCase().includes(q)).slice(0, 8)
  }, [query, graph.nodes])

  const paint = useCallback((n, ctx, scale) => {
    const dimmed = selected && !pathNodes.has(n.id)
    const color = nodeColor(n)
    const base = n.node_type === 'Module' ? 3.2 : 3.6
    const r = base + Math.min(6, (n.finding_count || 0) * 2) + (n.entry_kind ? 1.5 : 0)
    ctx.globalAlpha = dimmed ? 0.15 : 1
    if (n.finding_count > 0 || n.entry_kind || pathNodes.has(n.id)) {
      ctx.shadowColor = color
      ctx.shadowBlur = n.finding_count > 0 && n.reachability === 'reachable' ? 18 : 10
    }
    ctx.fillStyle = color
    ctx.beginPath()
    if (n.node_type === 'Module') ctx.rect(n.x - r, n.y - r, r * 2, r * 2)
    else ctx.arc(n.x, n.y, r, 0, 2 * Math.PI)
    ctx.fill()
    ctx.shadowBlur = 0
    if (selected && selected.id === n.id) {
      ctx.strokeStyle = '#B4FF39'; ctx.lineWidth = 1.5 / scale
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 4 / scale + 2, 0, 2 * Math.PI); ctx.stroke()
    }
    const small = graph.nodes.length <= 90
    const showLabel = (small && scale > 0.6) || scale > 2.2 || (hover && hover.id === n.id) || pathNodes.has(n.id) || (n.finding_count > 0 && scale > 0.8)
    if (showLabel && !dimmed) {
      const label = prettyFn(n.name === '__top_level__' ? (n.file_path || '').split('/').pop() : n.name)
      const fs = Math.max(11 / scale, 2.5)
      ctx.font = `${fs}px "JetBrains Mono Variable", monospace`
      ctx.fillStyle = n.finding_count > 0 ? '#ffb3b9' : 'rgba(227,231,224,0.85)'
      ctx.fillText(label, n.x + r + 2, n.y + fs / 3)
    }
    ctx.globalAlpha = 1
  }, [selected, pathNodes, hover, graph.nodes.length])

  const sel = selected && graph.nodes.find((n) => n.id === selected.id)

  return (
    <div className="relative h-[calc(100vh-96px)] w-full">
      <div ref={box} className="absolute inset-0">
        {error && <div className="p-10"><ErrorState error={error} onRetry={reload} /></div>}
        {loading && !data && <div className="flex h-full items-center justify-center"><Spinner size={28} /></div>}
        {data && (
          <ForceGraph2D
            ref={fg}
            width={size.w}
            height={size.h}
            graphData={graph}
            backgroundColor="rgba(0,0,0,0)"
            nodeRelSize={4}
            nodeCanvasObject={paint}
            nodePointerAreaPaint={(n, color, ctx) => { ctx.fillStyle = color; ctx.beginPath(); ctx.arc(n.x, n.y, 7, 0, 2 * Math.PI); ctx.fill() }}
            linkColor={(l) => {
              const k = `${l.source.id ?? l.source}->${l.target.id ?? l.target}`
              if (pathLinks.has(k)) return 'rgba(180,255,57,0.95)'
              if (selected) return 'rgba(255,255,255,0.03)'
              return l.kind === 'import' ? 'rgba(180,255,57,0.10)' : 'rgba(227,231,224,0.16)'
            }}
            linkWidth={(l) => (pathLinks.has(`${l.source.id ?? l.source}->${l.target.id ?? l.target}`) ? 2.2 : 0.7)}
            linkDirectionalArrowLength={3.2}
            linkDirectionalArrowRelPos={0.92}
            linkDirectionalParticles={(l) => (pathLinks.has(`${l.source.id ?? l.source}->${l.target.id ?? l.target}`) ? 3 : 0)}
            linkDirectionalParticleWidth={2.4}
            linkDirectionalParticleColor={() => '#B4FF39'}
            linkLineDash={(l) => (l.kind === 'import' ? [2, 3] : null)}
            onNodeClick={focusNode}
            onNodeHover={setHover}
            onBackgroundClick={() => setSelected(null)}
            cooldownTicks={140}
            d3VelocityDecay={0.3}
            onEngineStop={() => { if (!target && fg.current && !selected) fg.current.zoomToFit(600, 90) }}
          />
        )}
      </div>

      {/* top-left controls */}
      <div className="pointer-events-none absolute left-4 top-4 flex max-w-[calc(100%-2rem)] flex-col gap-3 md:left-8">
        <div data-tour="graph-controls" className="pointer-events-auto glass flex flex-wrap items-center gap-3 px-4 py-3">
          <Link to={`/scans/${scanId}`} className="text-fog-400 hover:text-lime" aria-label="Back"><ArrowLeft size={16} /></Link>
          <div className="mr-2">
            <div className="flex items-center gap-2"><Label>Call graph</Label><InfoHint title="Call graph" learn="call-graph">Dots are functions, squares are files, arrows are calls. Click a dot to highlight the path from an entry point to it.</InfoHint></div>
            <div className="mt-1 max-w-[220px] truncate font-display text-lg text-fog-50">{scan.data?.project_name || '…'}</div>
          </div>
          <div className="flex gap-1">
            {[['all', 'All'], ['reachable', 'Live code'], ['findings', 'Attack paths']].map(([k, l]) => (
              <button key={k} className={`chip ${focus === k ? 'chip-active' : ''}`} onClick={() => { setSelected(null); setFocus(k) }}>{l}</button>
            ))}
          </div>
          <button className={`chip ${modules ? 'chip-active' : ''}`} onClick={() => setModules((m) => !m)} title="Show module (file) nodes"><Layers size={12} /> Modules</button>
          <button className="chip" onClick={() => fg.current?.zoomToFit(500, 80)} title="Fit to screen"><Maximize2 size={12} /></button>
        </div>
        <div className="pointer-events-auto relative w-72">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-fog-500" />
          <input className="input py-2 pl-9" placeholder="Find a function or file…" value={query} onChange={(e) => setQuery(e.target.value)} />
          {matches.length > 0 && (
            <div className="absolute z-10 mt-2 w-full overflow-hidden rounded-xl border border-white/10 bg-ink-850/95 backdrop-blur-xl">
              {matches.map((n) => (
                <button key={n.id} onClick={() => { focusNode(n); setQuery('') }} className="block w-full px-3 py-2 text-left hover:bg-white/5">
                  <div className="truncate font-mono text-xs text-fog-50">{prettyFn(n.name)}</div>
                  <div className="truncate text-[11px] text-fog-500">{n.file_path}</div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* legend */}
      <div data-tour="graph-legend" className="glass absolute bottom-4 left-4 hidden px-4 py-3 md:left-8 md:block">
        <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-[11px] text-fog-300">
          {[[COLORS.entry, 'Entry point'], [COLORS.vulnReach, 'Vulnerable · reachable'], [COLORS.reachable, 'Reachable'], [COLORS.vulnDead, 'Vulnerable · dead/startup'], [COLORS.startup, 'Startup only'], [COLORS.dead, 'Dead code']].map(([c, l]) => (
            <span key={l} className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-full" style={{ background: c, boxShadow: `0 0 8px ${c}` }} />{l}</span>
          ))}
          <span className="flex items-center gap-2"><span className="h-2.5 w-2.5" style={{ background: COLORS.module }} />Module / file</span>
          <span className="text-fog-500">{graph.nodes.length} nodes · {graph.links.length} edges</span>
        </div>
      </div>

      {/* details panel */}
      {sel && (
        <div className="glass absolute right-4 top-4 w-[min(360px,calc(100%-2rem))] animate-fade-up p-5 md:right-8">
          <div className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <Label>{sel.node_type === 'Module' ? 'Module' : 'Function'}</Label>
              <div className="mt-2 break-all font-mono text-sm text-fog-50">{prettyFn(sel.name)}</div>
              <div className="mt-1 break-all text-xs text-fog-500">{sel.file_path}:{sel.line}</div>
            </div>
            <button onClick={() => setSelected(null)} className="rounded-lg p-1 text-fog-400 hover:bg-white/5 hover:text-fog-50" aria-label="Close"><X size={16} /></button>
          </div>
          <div className="mt-4 flex flex-wrap gap-2">
            <ReachBadge status={sel.reachability} />
            {sel.entry_kind && <span className="rounded-full border border-lime/40 bg-lime/10 px-2.5 py-0.5 text-[11px] text-lime">entry · {sel.entry_kind}</span>}
          </div>
          <div className="mt-5 grid grid-cols-3 gap-3 text-center">
            <div><div className="font-display text-2xl text-fog-50">{sel.finding_count}</div><div className="text-[10px] text-fog-500">findings</div></div>
            <div><div className="font-display text-2xl text-fog-50">{Math.round(sel.max_risk || 0)}</div><div className="text-[10px] text-fog-500">max risk</div></div>
            <div><div className="font-display text-2xl text-fog-50">{sel.ai_probability != null ? pct(sel.ai_probability) : '–'}</div><div className="text-[10px] text-fog-500">AI score</div></div>
          </div>
          <div className="mt-5 border-t border-white/[0.06] pt-4 text-xs text-fog-400">
            {pathNodes.size > 1 ? <span className="flex items-center gap-2"><Crosshair size={13} className="text-lime" />Highlighted: path from an entry point ({pathNodes.size - 1} hops)</span>
              : 'No entry point reaches this node in the current view.'}
          </div>
          {sel.finding_count > 0 && (
            <Link to={`/scans/${scanId}?q=${encodeURIComponent(sel.name)}`} className="btn-primary mt-4 w-full">View findings</Link>
          )}
        </div>
      )}
    </div>
  )
}
