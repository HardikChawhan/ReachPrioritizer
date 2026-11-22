import { useEffect, useRef } from 'react'

/**
 * Animated particle cloud (canvas, no dependencies).
 * Points sit on a few blob-shaped clusters joined by faint links — an abstract
 * call graph that "breathes". Respects prefers-reduced-motion.
 */
export default function ParticleField({ className = '', density = 1, hot = true }) {
  const ref = useRef(null)

  useEffect(() => {
    const canvas = ref.current
    if (!canvas) return undefined
    const ctx = canvas.getContext('2d')
    const reduce = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    let w = 0; let h = 0; let raf = 0; let t = 0
    const dpr = Math.min(2, window.devicePixelRatio || 1)

    const clusters = [
      { x: 0.55, y: 0.46, r: 0.22, n: 900 },
      { x: 0.36, y: 0.6, r: 0.11, n: 260 },
      { x: 0.74, y: 0.34, r: 0.12, n: 300 },
      { x: 0.68, y: 0.68, r: 0.08, n: 160 },
    ]
    const pts = []
    for (const c of clusters) {
      for (let i = 0; i < c.n * density; i++) {
        const a = Math.random() * Math.PI * 2
        const rr = c.r * Math.pow(Math.random(), 0.9) * (0.75 + 0.25 * Math.sin(a * 3))
        pts.push({
          bx: c.x + Math.cos(a) * rr * 1.25, by: c.y + Math.sin(a) * rr,
          ph: Math.random() * Math.PI * 2, sp: 0.4 + Math.random() * 0.8,
          s: Math.random() < 0.06 ? 1.9 : 0.5 + Math.random() * 0.9,
          hot: hot && Math.random() < 0.012,
        })
      }
    }
    const hubs = pts.filter((_, i) => i % 41 === 0)

    const resize = () => {
      const rect = canvas.getBoundingClientRect()
      w = rect.width; h = rect.height
      canvas.width = w * dpr; canvas.height = h * dpr
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0)
    }
    resize()
    const ro = new ResizeObserver(resize)
    ro.observe(canvas)

    const draw = () => {
      t += reduce ? 0 : 0.006
      ctx.clearRect(0, 0, w, h)
      // soft core glow behind the cloud
      const g = ctx.createRadialGradient(w * 0.56, h * 0.47, 0, w * 0.56, h * 0.47, Math.min(w, h) * 0.45)
      g.addColorStop(0, 'rgba(180,255,57,0.16)')
      g.addColorStop(1, 'rgba(180,255,57,0)')
      ctx.fillStyle = g
      ctx.fillRect(0, 0, w, h)
      ctx.globalCompositeOperation = 'lighter'
      const pos = (p) => [
        (p.bx + Math.sin(t * p.sp + p.ph) * 0.006) * w,
        (p.by + Math.cos(t * p.sp * 0.8 + p.ph) * 0.008) * h,
      ]
      ctx.lineWidth = 0.6
      for (let i = 0; i < hubs.length; i++) {
        const [x1, y1] = pos(hubs[i])
        for (let j = i + 1; j < hubs.length; j++) {
          const [x2, y2] = pos(hubs[j])
          const d = Math.hypot(x1 - x2, y1 - y2)
          if (d < Math.min(w, h) * 0.16) {
            ctx.strokeStyle = `rgba(180,255,57,${0.13 * (1 - d / (Math.min(w, h) * 0.16))})`
            ctx.beginPath(); ctx.moveTo(x1, y1); ctx.lineTo(x2, y2); ctx.stroke()
          }
        }
      }
      for (const p of pts) {
        const [x, y] = pos(p)
        const tw = 0.55 + 0.45 * Math.sin(t * 3 * p.sp + p.ph)
        if (p.hot) {
          ctx.fillStyle = `rgba(255,77,94,${0.5 + 0.5 * tw})`
          ctx.shadowColor = '#FF4D5E'; ctx.shadowBlur = 14
          ctx.beginPath(); ctx.arc(x, y, 2.6, 0, Math.PI * 2); ctx.fill()
          ctx.shadowBlur = 0
        } else {
          ctx.fillStyle = `rgba(180,255,57,${0.25 + 0.6 * tw * (p.s > 2 ? 1 : 0.7)})`
          ctx.beginPath(); ctx.arc(x, y, p.s, 0, Math.PI * 2); ctx.fill()
        }
      }
      ctx.globalCompositeOperation = 'source-over'
      raf = requestAnimationFrame(draw)
    }
    draw()
    return () => { cancelAnimationFrame(raf); ro.disconnect() }
  }, [density, hot])

  return <canvas ref={ref} className={`h-full w-full ${className}`} aria-hidden="true" />
}
