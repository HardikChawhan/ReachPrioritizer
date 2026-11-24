import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import ForceGraph2D from 'react-force-graph-2d'
import { Maximize2 } from 'lucide-react'
import { prettyFn } from '../lib/format'

export const DIFF_COLORS = {
  fixed: '#B4FF39',
  new: '#FF4D5E',
  open: '#FF9442',
  added: '#6FD3FF',
  removed: '#5a2e34',
  entry: '#E3E7E0',
  reachable: '#8D958A',
  other: '#394039',
}

function colorOf(n, status) {
  const s = status[n.node_id]
  if (s === 'fixed' || s === 'new' || s === 'open') return DIFF_COLORS[s]
  if (s === 'removed') return DIFF_COLORS.removed
  if (s === 'added') return DIFF_COLORS.added
  if (n.entry_kind) return DIFF_COLORS.entry
  return n.reachability === 'reachable' ? DIFF_COLORS.reachable : DIFF_COLORS.other
}

function useSize(ref) {
  const [size, setSize] = useState({ w: 500, h: 420 })
  useEffect(() => {
    if (!ref.current) return undefined
    const ro = new ResizeObserver(([e]) => setSize({ w: e.contentRect.width, h: e.contentRect.height }))
    ro.observe(ref.current)
    return () => ro.disconnect()
  }, [ref])
  return size
}

/**
 * One side of the side-by-side comparison. Nodes are coloured by their diff
 * status; `path` (list of node ids) is drawn as a glowing attack path.
 */
export default function DiffGraph({ graph, status = {}, path = [], selectedId, onSelect, accent = '#B4FF39', emptyText }) {
  const fg = useRef(null)
  const box = useRef(null)
  const size = useSize(box)
  const [hover, setHover] = useState(null)

  const data = useMemo(() => {
    if (!graph) return { nodes: [], links: [] }
    const nodes = graph.nodes.map((n) => ({ ...n, id: n.node_id }))
    const ids = new Set(nodes.map((n) => n.id))
    const links = graph.edges.filter((e) => ids.has(e.caller_id) && ids.has(e.callee_id)).map((e) => ({ source: e.caller_id, target: e.callee_id }))
    return { nodes, links }
  }, [graph])

  const pathNodes = useMemo(() => new Set(path), [path])
  const pathLinks = useMemo(() => {
    const s = new Set()
    for (let i = 1; i < path.length; i++) s.add(`${path[i - 1]}->${path[i]}`)
    return s
  }, [path])

  useEffect(() => {
    const g = fg.current
    if (!g || !data.nodes.length) return
    g.d3Force('charge')?.strength(-110).distanceMax(220)
    g.d3Force('link')?.distance(42)
    const nodes = data.nodes
    g.d3Force('gravity', (alpha) => {
      for (const n of nodes) { n.vx -= (n.x || 0) * 0.06 * alpha; n.vy -= (n.y || 0) * 0.06 * alpha }
    })
    g.d3ReheatSimulation?.()
  }, [data])

  const key = (l) => `${l.source.id ?? l.source}->${l.target.id ?? l.target}`

  const paint = useCallback((n, ctx, scale) => {
    const active = pathNodes.size > 0
    const onPath = pathNodes.has(n.id)
    const dim = active && !onPath
    const st = status[n.node_id]
    const c = colorOf(n, status)
    const isModule = n.node_type === 'Module'
    const r = (st === 'fixed' || st === 'new' || st === 'open') ? 5.5 : n.entry_kind ? 4.5 : isModule ? 2.8 : 3.4
    ctx.globalAlpha = dim ? 0.18 : 1
    if (st === 'fixed' || st === 'new' || onPath) { ctx.shadowColor = onPath ? accent : c; ctx.shadowBlur = 16 }
    ctx.fillStyle = isModule && !st ? '#4a5148' : c
    ctx.beginPath()
    if (isModule) ctx.rect(n.x - r, n.y - r, r * 2, r * 2)
    else ctx.arc(n.x, n.y, r, 0, 2 * Math.PI)
    ctx.fill()
    ctx.shadowBlur = 0
    if (st === 'removed') {
      ctx.strokeStyle = '#ff8a95'; ctx.setLineDash([2, 2]); ctx.lineWidth = 1 / scale
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 2, 0, 2 * Math.PI); ctx.stroke(); ctx.setLineDash([])
    }
    if (selectedId === n.id) {
      ctx.strokeStyle = accent; ctx.lineWidth = 1.6 / scale
      ctx.beginPath(); ctx.arc(n.x, n.y, r + 4, 0, 2 * Math.PI); ctx.stroke()
    }
    const show = onPath || st === 'fixed' || st === 'new' || (hover && hover.id === n.id) || scale > 2.4 || (data.nodes.length < 40 && scale > 0.9)
    if (show && !dim) {
      const fs = Math.max(10 / scale, 2.4)
      ctx.font = `${fs}px "JetBrains Mono Variable", monospace`
      ctx.fillStyle = st === 'new' ? '#ffb3b9' : st === 'fixed' ? '#dcff9e' : 'rgba(227,231,224,0.85)'
      ctx.fillText(isModule ? (n.file_path || '').split('/').pop() : prettyFn(n.name), n.x + r + 2, n.y + fs / 3)
    }
    ctx.globalAlpha = 1
  }, [pathNodes, status, selectedId, hover, accent, data.nodes.length])

  return (
    <div ref={box} className="relative h-full w-full">
      {data.nodes.length === 0 ? (
        <div className="flex h-full items-center justify-center px-6 text-center text-sm text-fog-500">{emptyText || 'No functions on attack paths.'}</div>
      ) : (
        <ForceGraph2D
          ref={fg}
          width={size.w}
          height={size.h}
          graphData={data}
          backgroundColor="rgba(0,0,0,0)"
          nodeCanvasObject={paint}
          nodePointerAreaPaint={(n, color, ctx) => { ctx.fillStyle = color; ctx.beginPath(); ctx.arc(n.x, n.y, 7, 0, 2 * Math.PI); ctx.fill() }}
          linkColor={(l) => (pathLinks.has(key(l)) ? accent : pathNodes.size ? 'rgba(255,255,255,0.04)' : 'rgba(227,231,224,0.16)')}
          linkWidth={(l) => (pathLinks.has(key(l)) ? 2.2 : 0.7)}
          linkDirectionalArrowLength={3}
          linkDirectionalArrowRelPos={0.9}
          linkDirectionalParticles={(l) => (pathLinks.has(key(l)) ? 3 : 0)}
          linkDirectionalParticleWidth={2.4}
          linkDirectionalParticleColor={() => accent}
          onNodeClick={(n) => onSelect && onSelect(n.id)}
          onNodeHover={setHover}
          onBackgroundClick={() => onSelect && onSelect(null)}
          cooldownTicks={120}
          d3VelocityDecay={0.3}
          onEngineStop={() => fg.current?.zoomToFit(500, 40)}
        />
      )}
      {data.nodes.length > 0 && (
        <button type="button" className="absolute bottom-3 right-3 rounded-lg border border-white/10 bg-ink-900/80 p-1.5 text-fog-400 hover:text-lime" onClick={() => fg.current?.zoomToFit(500, 40)} aria-label="Fit"><Maximize2 size={13} /></button>
      )}
    </div>
  )
}
