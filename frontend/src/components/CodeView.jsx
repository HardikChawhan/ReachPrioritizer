import { useMemo, useState } from 'react'
import { Check, Copy } from 'lucide-react'

const KEYWORDS = new Set('const let var function return if else for while of in new class extends async await try catch throw import from export default require module exports this typeof null undefined true false'.split(' '))
const SINKS = new Set('eval exec execSync spawn execFile query readFileSync readFile redirect send unserialize parseXmlString innerHTML write download sendFile'.split(' '))

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
}

/** Minimal, safe JS highlighter (escapes first, then wraps tokens). */
function highlight(line) {
  const parts = []
  const re = /(\/\/.*$)|('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*"|`(?:[^`\\]|\\.)*`)/g
  let last = 0
  let m
  while ((m = re.exec(line))) {
    parts.push({ t: 'code', v: line.slice(last, m.index) })
    parts.push({ t: m[1] ? 'comment' : 'string', v: m[0] })
    last = m.index + m[0].length
  }
  parts.push({ t: 'code', v: line.slice(last) })
  return parts.map((p) => {
    const e = escapeHtml(p.v)
    if (p.t === 'comment') return `<span class="text-fog-500 italic">${e}</span>`
    if (p.t === 'string') return `<span class="text-[#C8FF6B]">${e}</span>`
    // single pass so inserted markup is never re-scanned
    return e.replace(/&[a-z]+;|[A-Za-z_$][\w$]*|\d+/g, (w) => {
      if (w.startsWith('&')) return w
      if (SINKS.has(w)) return `<span class="text-[#ff8a95]">${w}</span>`
      if (KEYWORDS.has(w)) return `<span class="text-[#9fb4ff]">${w}</span>`
      if (/^\d+$/.test(w)) return `<span class="text-[#ffd54a]">${w}</span>`
      return w
    })
  }).join('')
}

export default function CodeView({ code = '', startLine = 1, highlightLines = [], file }) {
  const [copied, setCopied] = useState(false)
  const lines = useMemo(() => (code || '').replace(/\r\n/g, '\n').split('\n'), [code])
  const hl = new Set(highlightLines)
  const copy = () => {
    navigator.clipboard?.writeText(code).then(() => { setCopied(true); setTimeout(() => setCopied(false), 1500) })
  }
  return (
    <div className="overflow-hidden rounded-2xl border border-white/[0.07] bg-ink-900/80">
      <div className="flex items-center justify-between border-b border-white/[0.06] px-4 py-2.5">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-white/10" /><span className="h-2.5 w-2.5 rounded-full bg-white/10" /><span className="h-2.5 w-2.5 rounded-full bg-white/10" />
          </div>
          <span className="truncate font-mono text-xs text-fog-400">{file}</span>
        </div>
        <button onClick={copy} className="flex items-center gap-1.5 rounded-md px-2 py-1 text-xs text-fog-400 hover:bg-white/5 hover:text-fog-100">
          {copied ? <Check size={13} className="text-lime" /> : <Copy size={13} />} {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <div className="max-h-[520px] overflow-auto py-3 font-mono text-[12.5px] leading-6">
        {lines.map((l, i) => {
          const n = startLine + i
          const on = hl.has(n)
          return (
            <div key={i} className={`code-line flex ${on ? 'bg-risk-critical/[0.12]' : ''}`}>
              <span className={`w-14 shrink-0 select-none border-r pr-3 text-right tabular-nums ${on ? 'border-risk-critical text-[#ff8a95]' : 'border-transparent text-fog-600'}`}>{n}</span>
              <code className="whitespace-pre pl-4 pr-6 text-fog-100" dangerouslySetInnerHTML={{ __html: highlight(l) || ' ' }} />
            </div>
          )
        })}
      </div>
    </div>
  )
}
