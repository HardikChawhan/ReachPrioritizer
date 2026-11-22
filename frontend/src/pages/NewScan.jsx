import { useCallback, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { FileArchive, ShieldCheck, UploadCloud, X } from 'lucide-react'
import { Card, Label, PageHeader, ProgressBar } from '../components/ui'
import { api } from '../lib/api'
import { bytes } from '../lib/format'

export default function NewScan() {
  const [file, setFile] = useState(null)
  const [name, setName] = useState('')
  const [drag, setDrag] = useState(false)
  const [progress, setProgress] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const input = useRef(null)
  const navigate = useNavigate()

  const pick = useCallback((f) => {
    setError(null)
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.zip')) { setError('Please choose a .zip archive of the project.'); return }
    if (f.size > 100 * 1024 * 1024) { setError('The archive is larger than 100 MB.'); return }
    setFile(f)
    if (!name) setName(f.name.replace(/\.zip$/i, ''))
  }, [name])

  const submit = async () => {
    if (!file) return
    setBusy(true); setError(null); setProgress(0)
    try {
      const res = await api.upload(file, name.trim(), setProgress)
      navigate(`/scans/${res.scan.scan_id}`)
    } catch (e) {
      setError(e.message); setBusy(false)
    }
  }

  return (
    <div className="mx-auto max-w-4xl">
      <PageHeader label="New scan" title="Drop a project." fade="We'll find the reachable bugs." />

      <div className="mt-10 grid gap-6 lg:grid-cols-[1.5fr_1fr]">
        <Card className="p-2" data-tour="dropzone">
          <div
            role="button" tabIndex={0}
            onClick={() => !busy && input.current?.click()}
            onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
            onDragLeave={() => setDrag(false)}
            onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files?.[0]) }}
            className={`relative flex min-h-[300px] cursor-pointer flex-col items-center justify-center overflow-hidden rounded-xl border border-dashed px-6 py-12 text-center transition-all duration-300 ${drag ? 'border-lime bg-lime/[0.06] shadow-glow' : 'border-white/15 hover:border-lime/40 hover:bg-white/[0.02]'}`}
          >
            <div className="pointer-events-none absolute inset-x-0 -top-20 mx-auto h-40 w-2/3 rounded-full bg-lime/15 blur-3xl" />
            <input ref={input} type="file" accept=".zip,application/zip" className="hidden" onChange={(e) => pick(e.target.files?.[0])} />
            {!file ? (
              <>
                <div className="relative mb-6 animate-float rounded-2xl border border-lime/25 bg-lime/[0.07] p-5 text-lime shadow-glow-sm"><UploadCloud size={30} /></div>
                <div className="font-display text-2xl font-light text-fog-50">Drag & drop a .zip</div>
                <div className="mt-2 text-sm text-fog-400">or click to browse · up to 100 MB · node_modules is ignored</div>
              </>
            ) : (
              <div className="relative flex w-full max-w-sm items-center gap-4 rounded-xl border border-white/10 bg-ink-850/80 p-4 text-left">
                <FileArchive className="shrink-0 text-lime" />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm text-fog-50">{file.name}</div>
                  <div className="text-xs text-fog-500">{bytes(file.size)}</div>
                </div>
                {!busy && <button onClick={(e) => { e.stopPropagation(); setFile(null) }} className="rounded-lg p-1.5 text-fog-400 hover:bg-white/5 hover:text-fog-50" aria-label="Remove"><X size={16} /></button>}
              </div>
            )}
          </div>
          <div className="space-y-4 p-4">
            <div>
              <label className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-fog-400" htmlFor="pname">Project name</label>
              <input id="pname" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="my-api" maxLength={120} />
            </div>
            {busy && (
              <div>
                <div className="mb-2 flex justify-between text-xs text-fog-400"><span>{progress < 1 ? 'Uploading…' : 'Starting analysis…'}</span><span>{Math.round(progress * 100)}%</span></div>
                <ProgressBar value={progress * 100} />
              </div>
            )}
            {error && <div className="rounded-xl border border-risk-critical/30 bg-risk-critical/10 px-4 py-3 text-sm text-[#ff9aa3]">{error}</div>}
            <button className="btn-primary w-full py-3" disabled={!file || busy} onClick={submit}>
              {busy ? 'Working…' : 'Upload & scan'}
            </button>
          </div>
        </Card>

        <div data-tour="scan-info" className="flex flex-col gap-4">
          <Card className="p-6">
            <Label>What gets analyzed</Label>
            <ul className="mt-5 space-y-3 text-sm text-fog-300">
              {['.js .mjs .cjs .jsx .ts .tsx sources', 'Express, Fastify, Koa, http, Next.js API routes, serverless handlers', 'Cross-file calls, classes, routers & callbacks', 'Test, build and tooling files are skipped automatically'].map((t) => (
                <li key={t} className="flex gap-3"><span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-lime" />{t}</li>
              ))}
            </ul>
          </Card>
          <Card className="p-6">
            <div className="flex items-center gap-3 text-lime"><ShieldCheck size={18} /><Label>Safe by design</Label></div>
            <p className="mt-4 text-sm leading-relaxed text-fog-400">
              Code is only parsed, never executed. Archives are checked for path traversal, symlinks and zip bombs before anything is unpacked.
            </p>
          </Card>
        </div>
      </div>
    </div>
  )
}
