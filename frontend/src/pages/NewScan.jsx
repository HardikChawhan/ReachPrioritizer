import { useCallback, useEffect, useRef, useState } from 'react'
import { Link, useNavigate, useSearchParams } from 'react-router-dom'
import { FileArchive, GitBranch, Github, GitCompareArrows, ShieldCheck, UploadCloud, X } from 'lucide-react'
import { Card, Label, PageHeader, ProgressBar } from '../components/ui'
import { api } from '../lib/api'
import { bytes } from '../lib/format'

const EXAMPLES = ['https://github.com/OWASP/NodeGoat', 'https://github.com/appsecco/dvna']
const GH_RE = /^(https?:\/\/)?(www\.)?github\.com\/[\w.-]+\/[\w.-]+(\.git)?(\/tree\/\S+)?\/?$|^[\w.-]+\/[\w.-]+$/

function Tab({ active, onClick, icon: Icon, children, tour }) {
  return (
    <button
      type="button" onClick={onClick} data-tour={tour}
      className={`flex flex-1 items-center justify-center gap-2 rounded-full px-4 py-2 text-sm transition-all ${active ? 'bg-lime text-ink-950 shadow-glow-sm' : 'text-fog-300 hover:bg-white/5 hover:text-fog-50'}`}
    >
      <Icon size={15} />{children}
    </button>
  )
}

export default function NewScan() {
  const [params] = useSearchParams()
  const versionOf = params.get('project')
  const [mode, setMode] = useState(params.get('source') === 'github' ? 'github' : 'zip')
  const [file, setFile] = useState(null)
  const [name, setName] = useState('')
  const [repo, setRepo] = useState('')
  const [branch, setBranch] = useState('')
  const [drag, setDrag] = useState(false)
  const [progress, setProgress] = useState(0)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [project, setProject] = useState(null)
  const input = useRef(null)
  const navigate = useNavigate()

  useEffect(() => {
    if (!versionOf) return
    api.project(versionOf).then((p) => { setProject(p); if (p.source_type === 'github') setMode('github') }).catch(() => setProject(null))
  }, [versionOf])

  const pick = useCallback((f) => {
    setError(null)
    if (!f) return
    if (!f.name.toLowerCase().endsWith('.zip')) { setError('Please choose a .zip archive of the project.'); return }
    if (f.size > 100 * 1024 * 1024) { setError('The archive is larger than 100 MB.'); return }
    setFile(f)
    if (!name && !versionOf) setName(f.name.replace(/\.zip$/i, ''))
  }, [name, versionOf])

  const submitZip = async () => {
    if (!file) return
    setBusy(true); setError(null); setProgress(0)
    try {
      const res = await api.upload(file, name.trim(), setProgress, versionOf)
      navigate(`/scans/${res.scan.scan_id}`)
    } catch (e) {
      setError(e.message); setBusy(false)
    }
  }

  const refreshMode = Boolean(versionOf && project?.source_type === 'github')

  const submitGithub = async () => {
    setBusy(true); setError(null)
    try {
      const res = refreshMode ? await api.refreshGithub(versionOf) : await api.fromGithub(repo.trim(), branch.trim(), name.trim())
      navigate(`/scans/${res.scan.scan_id}`)
    } catch (e) {
      setError(e.message); setBusy(false)
    }
  }

  const repoOk = GH_RE.test(repo.trim())

  return (
    <div className="mx-auto max-w-4xl">
      {versionOf ? (
        <PageHeader label="New version" title={project ? project.name : 'Project'} fade="— scan the updated code." />
      ) : (
        <PageHeader label="New scan" title="Drop a project." fade="We'll find the reachable bugs." />
      )}
      {versionOf && (
        <div className="mt-6 flex items-start gap-3 rounded-xl border border-lime/20 bg-lime/[0.05] px-4 py-3 text-sm text-fog-300">
          <GitCompareArrows size={18} className="mt-0.5 shrink-0 text-lime" />
          <span>The new scan is added to the same project, so you can <b className="text-fog-50">compare it with the previous scan</b> and see what you fixed.</span>
        </div>
      )}

      <div className="mt-10 grid gap-6 lg:grid-cols-[1.5fr_1fr]">
        <Card className="p-2" data-tour="dropzone">
          {!refreshMode && !versionOf && (
            <div className="m-2 flex gap-1 rounded-full border border-white/10 bg-ink-900/70 p-1">
              <Tab active={mode === 'zip'} onClick={() => setMode('zip')} icon={UploadCloud}>Upload ZIP</Tab>
              <Tab active={mode === 'github'} onClick={() => setMode('github')} icon={Github} tour="github-tab">GitHub link</Tab>
            </div>
          )}

          {mode === 'zip' && !refreshMode ? (
            <>
              <div
                role="button" tabIndex={0}
                onClick={() => !busy && input.current?.click()}
                onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && input.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDrag(true) }}
                onDragLeave={() => setDrag(false)}
                onDrop={(e) => { e.preventDefault(); setDrag(false); pick(e.dataTransfer.files?.[0]) }}
                className={`relative flex min-h-[280px] cursor-pointer flex-col items-center justify-center overflow-hidden rounded-xl border border-dashed px-6 py-12 text-center transition-all duration-300 ${drag ? 'border-lime bg-lime/[0.06] shadow-glow' : 'border-white/15 hover:border-lime/40 hover:bg-white/[0.02]'}`}
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
                  <label className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-fog-400" htmlFor="pname">{versionOf ? 'Version label (optional)' : 'Project name'}</label>
                  <input id="pname" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder={versionOf ? 'after-fixes' : 'my-api'} maxLength={120} />
                </div>
                {busy && (
                  <div>
                    <div className="mb-2 flex justify-between text-xs text-fog-400"><span>{progress < 1 ? 'Uploading…' : 'Starting analysis…'}</span><span>{Math.round(progress * 100)}%</span></div>
                    <ProgressBar value={progress * 100} />
                  </div>
                )}
                {error && <div className="rounded-xl border border-risk-critical/30 bg-risk-critical/10 px-4 py-3 text-sm text-[#ff9aa3]">{error}</div>}
                <button className="btn-primary w-full py-3" disabled={!file || busy} onClick={submitZip}>
                  {busy ? 'Working…' : versionOf ? 'Upload new version & scan' : 'Upload & scan'}
                </button>
              </div>
            </>
          ) : (
            <div className="space-y-5 p-4">
              <div className="relative overflow-hidden rounded-xl border border-white/10 bg-ink-900/60 p-6">
                <div className="pointer-events-none absolute -right-16 -top-16 h-40 w-40 rounded-full bg-lime/10 blur-3xl" />
                <div className="flex items-center gap-3 text-lime"><Github size={22} /><span className="font-display text-xl font-light text-fog-50">{refreshMode ? 'Pull the latest code' : 'Scan a GitHub repository'}</span></div>
                <p className="mt-2 text-sm text-fog-400">
                  {refreshMode
                    ? <>We download <span className="font-mono text-fog-200">{project.source_url}</span> again and scan the newest commit.</>
                    : 'Paste the link of a public repository. We download it as a ZIP (same safety checks as an upload) and scan it — nothing is installed or run.'}
                </p>
              </div>
              {!refreshMode && (
                <>
                  <div>
                    <label className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-fog-400" htmlFor="repo">Repository link</label>
                    <input id="repo" className="input font-mono" value={repo} onChange={(e) => setRepo(e.target.value)} placeholder="https://github.com/owner/repo"
                      onKeyDown={(e) => e.key === 'Enter' && repoOk && !busy && submitGithub()} />
                    <div className="mt-2 flex flex-wrap gap-2 text-xs text-fog-500">
                      Try:
                      {EXAMPLES.map((u) => <button key={u} type="button" className="font-mono text-fog-300 underline decoration-dotted underline-offset-2 hover:text-lime" onClick={() => setRepo(u)}>{u.replace('https://github.com/', '')}</button>)}
                    </div>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <div>
                      <label className="mb-2 flex items-center gap-1.5 font-mono text-[11px] uppercase tracking-[0.16em] text-fog-400" htmlFor="branch"><GitBranch size={12} />Branch / tag</label>
                      <input id="branch" className="input font-mono" value={branch} onChange={(e) => setBranch(e.target.value)} placeholder="default branch" />
                    </div>
                    <div>
                      <label className="mb-2 block font-mono text-[11px] uppercase tracking-[0.16em] text-fog-400" htmlFor="gname">Project name</label>
                      <input id="gname" className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="owner/repo" maxLength={120} />
                    </div>
                  </div>
                </>
              )}
              {busy && (
                <div>
                  <div className="mb-2 text-xs text-fog-400">Downloading from GitHub…</div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-white/5"><div className="h-full w-full animate-shimmer rounded-full bg-gradient-to-r from-transparent via-lime/80 to-transparent bg-[length:200%_100%]" /></div>
                </div>
              )}
              {error && <div className="rounded-xl border border-risk-critical/30 bg-risk-critical/10 px-4 py-3 text-sm text-[#ff9aa3]">{error}</div>}
              <button className="btn-primary w-full py-3" disabled={(!refreshMode && !repoOk) || busy} onClick={submitGithub}>
                {busy ? 'Working…' : refreshMode ? 'Download latest & scan' : 'Download & scan'}
              </button>
              {!refreshMode && <p className="text-center text-xs text-fog-500">Public repositories only · up to 100 MB</p>}
            </div>
          )}
        </Card>

        <div data-tour="scan-info" className="flex flex-col gap-4">
          <Card className="p-6">
            <Label>What gets analyzed</Label>
            <ul className="mt-5 space-y-3 text-sm text-fog-300">
              {['.js .mjs .cjs .jsx .ts .tsx sources', 'Express, Fastify, Koa, http, Next.js API routes, serverless handlers', 'Cross-file calls, classes, routers & callbacks', 'package.json dependencies, checked against the OSV database', 'Test, build and tooling files are skipped automatically'].map((t) => (
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
          {versionOf && <Link to="/scans" className="text-center text-xs text-fog-500 hover:text-fog-300">Cancel</Link>}
        </div>
      </div>
    </div>
  )
}
