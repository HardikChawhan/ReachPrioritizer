import { useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { ArrowRight, FolderGit2, GitCompareArrows, Github, Play, Plus, Trash2, UploadCloud } from 'lucide-react'
import { Card, EmptyState, ErrorState, Label, PageHeader, RiskBadge, Skeleton, useAsync } from '../components/ui'
import { StatusDot } from './Dashboard'
import { api } from '../lib/api'
import { bytes, duration, riskOf, timeAgo } from '../lib/format'

export default function Scans() {
  const navigate = useNavigate()
  const scans = useAsync(() => api.scans(), [], { poll: 3000, until: (d) => !d.some((s) => ['queued', 'running'].includes(s.status)) })
  const projects = useAsync(() => api.projects(), [])
  const [busy, setBusy] = useState(null)

  const rescan = async (pid) => {
    setBusy(pid)
    try { const s = await api.startScan(pid); navigate(`/scans/${s.scan_id}`) } finally { setBusy(null) }
  }
  const removeScan = async (id) => {
    if (!window.confirm('Delete this scan and its results? This cannot be undone.')) return
    await api.deleteScan(id); scans.reload(); projects.reload()
  }
  const removeProject = async (p) => {
    if (!window.confirm(`Delete project "${p.name}", its uploaded archive and all of its scans? This cannot be undone.`)) return
    await api.deleteProject(p.project_id); scans.reload(); projects.reload()
  }

  return (
    <div>
      <PageHeader label="History" title="Scans" fade="& projects.">
        <Link to="/scan/new" className="btn-primary"><Plus size={15} /> New scan</Link>
      </PageHeader>

      <section className="mt-12">
        <Label>Projects</Label>
        <div className="mt-5 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {projects.loading && !projects.data && [0, 1, 2].map((i) => <Skeleton key={i} className="h-36" />)}
          {projects.error && <ErrorState error={projects.error} onRetry={projects.reload} />}
          {(projects.data || []).map((p) => (
            <Card key={p.project_id} hover className="flex flex-col p-5">
              <div className="flex items-start justify-between gap-3">
                <div className="flex min-w-0 items-center gap-3">
                  <div className="rounded-xl border border-lime/20 bg-lime/[0.06] p-2.5 text-lime">{p.source_type === 'github' ? <Github size={16} /> : <FolderGit2 size={16} />}</div>
                  <div className="min-w-0">
                    <div className="truncate font-display text-lg text-fog-50">{p.name}</div>
                    <div className="truncate text-xs text-fog-500">{p.file_count} source files · {bytes(p.size_bytes)}{p.source_ref ? ` · ${p.source_ref}` : ''}</div>
                  </div>
                </div>
                <button onClick={() => removeProject(p)} className="rounded-lg p-1.5 text-fog-500 hover:bg-risk-critical/10 hover:text-risk-critical" title="Delete project"><Trash2 size={15} /></button>
              </div>
              <div className="mt-4 text-xs text-fog-500">{p.scan_count} scan{p.scan_count === 1 ? '' : 's'} · last {timeAgo(p.last_scan_at || p.created_at)}</div>
              <div className="mt-4 grid grid-cols-2 gap-2">
                <button className="btn-ghost w-full" disabled={busy === p.project_id} onClick={() => rescan(p.project_id)}><Play size={14} /> {busy === p.project_id ? 'Starting…' : 'Rescan'}</button>
                <Link className="btn-ghost w-full" to={`/scan/new?project=${p.project_id}`} title="Scan an updated version of the code">{p.source_type === 'github' ? <Github size={14} /> : <UploadCloud size={14} />} New version</Link>
              </div>
              {(() => {
                const done = (scans.data || []).filter((x) => x.project_id === p.project_id && x.status === 'completed')
                return done.length >= 2 ? (
                  <Link className="btn-ghost mt-2 w-full" to={`/compare?base=${done[1].scan_id}&head=${done[0].scan_id}`}><GitCompareArrows size={14} /> Compare last two scans</Link>
                ) : null
              })()}
            </Card>
          ))}
        </div>
        {projects.data && projects.data.length === 0 && (
          <EmptyState icon={FolderGit2} title="No projects yet" action={<Link to="/scan/new" className="btn-primary">Upload a project</Link>}>Upload a ZIP to create your first project.</EmptyState>
        )}
      </section>

      <section className="mt-14">
        <Label>All scans</Label>
        <Card className="mt-5 overflow-hidden">
          <div className="hidden grid-cols-[2fr_1fr_1fr_1fr_1fr_80px] gap-4 border-b border-white/[0.06] px-5 py-3 font-mono text-[10px] uppercase tracking-[0.16em] text-fog-500 md:grid">
            <span>Project</span><span>Status</span><span>Findings</span><span>Actionable</span><span>Top risk</span><span />
          </div>
          {scans.loading && !scans.data && <div className="p-5"><Skeleton className="h-40" /></div>}
          {(scans.data || []).map((s) => {
            const sum = s.summary || {}
            return (
              <div key={s.scan_id} className="grid grid-cols-2 items-center gap-3 border-b border-white/[0.04] px-5 py-4 transition hover:bg-white/[0.02] md:grid-cols-[2fr_1fr_1fr_1fr_1fr_80px] md:gap-4">
                <Link to={`/scans/${s.scan_id}`} className="col-span-2 min-w-0 md:col-span-1">
                  <div className="truncate text-fog-50 hover:text-lime">{s.project_name}</div>
                  <div className="text-xs text-fog-500">{timeAgo(s.created_at)} · {duration(s.duration_ms)}</div>
                </Link>
                <StatusDot status={s.status} />
                <span className="font-mono text-sm tabular-nums text-fog-200">{s.status === 'completed' ? s.finding_count : '–'}</span>
                <span className={`font-mono text-sm tabular-nums ${sum.actionable ? 'text-risk-critical' : 'text-fog-400'}`}>{s.status === 'completed' ? sum.actionable ?? 0 : '–'}</span>
                <span>{s.status === 'completed' && sum.max_risk != null ? <RiskBadge category={riskOf(sum.max_risk)} /> : <span className="text-fog-600">–</span>}</span>
                <span className="flex items-center justify-end gap-1">
                  {!['queued', 'running'].includes(s.status) && (
                    <button onClick={() => removeScan(s.scan_id)} className="rounded-lg p-1.5 text-fog-500 hover:bg-risk-critical/10 hover:text-risk-critical" title="Delete scan"><Trash2 size={14} /></button>
                  )}
                  <Link to={`/scans/${s.scan_id}`} className="rounded-lg p-1.5 text-fog-500 hover:text-lime"><ArrowRight size={15} /></Link>
                </span>
              </div>
            )
          })}
          {scans.data && scans.data.length === 0 && <div className="px-5 py-10 text-center text-sm text-fog-500">No scans yet.</div>}
        </Card>
      </section>
    </div>
  )
}
