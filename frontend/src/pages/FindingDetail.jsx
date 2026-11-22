import { Link, useParams } from 'react-router-dom'
import { ArrowLeft, BrainCircuit, Crosshair, Lightbulb, Network, Route, Workflow } from 'lucide-react'
import AttackPath from '../components/AttackPath'
import CodeView from '../components/CodeView'
import { Card, ErrorState, InfoHint, Label, Pill, ReachBadge, RiskBadge, RiskRing, Skeleton, TaintBadge, useAsync } from '../components/ui'
import { api } from '../lib/api'
import { CWE_INFO, REACH, SEVERITY_LABEL, TAINT, cweName, pct, prettyFn } from '../lib/format'

function Breakdown({ f }) {
  const b = f.risk_breakdown || {}
  const rows = [
    { label: 'Severity', weight: '45%', value: b.severity_weight, contrib: b.severity_contribution, note: SEVERITY_LABEL[f.severity] || f.severity, color: '#FF9442' },
    { label: 'Exploitability', weight: '35%', value: b.exploitability_weight, contrib: b.exploitability_contribution, note: (TAINT[f.taint] || TAINT.unknown).label, color: '#FF4D5E' },
    { label: 'AI probability', weight: '20%', value: b.ai_probability, contrib: b.ai_contribution, note: pct(f.vulnerability_probability), color: '#B4FF39' },
  ]
  return (
    <Card className="p-6" data-tour="score">
      <div className="flex items-center gap-2"><Label>Why this score</Label><InfoHint title="Risk score" learn="risk-score" align="right">100 × reachability × (0.45 severity + 0.35 exploitability + 0.20 AI). Try the calculator on the Learn page.</InfoHint></div>
      <div className="mt-5 flex items-center gap-5">
        <RiskRing score={f.risk_score} size={84} stroke={6} showLabel />
        <div className="text-sm leading-relaxed text-fog-400">
          <span className="font-mono text-fog-200">100 × reach × (0.45·sev + 0.35·exploit + 0.20·AI)</span>
          <div className="mt-1">Reachability multiplier <b className="font-medium text-fog-50">×{b.reachability_multiplier ?? '–'}</b> — {(REACH[f.reachability_status] || REACH.unknown).hint.toLowerCase()}.</div>
        </div>
      </div>
      <div className="mt-6 space-y-4">
        {rows.map((r) => (
          <div key={r.label}>
            <div className="mb-1.5 flex items-baseline justify-between text-sm">
              <span className="text-fog-300">{r.label} <span className="font-mono text-[10px] text-fog-600">w {r.weight}</span></span>
              <span className="font-mono text-xs text-fog-400">{r.note} · <span className="text-fog-50">+{(r.contrib ?? 0).toFixed(1)}</span></span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-white/[0.05]">
              <div className="h-full rounded-full" style={{ width: `${Math.max(2, (r.value || 0) * 100)}%`, background: r.color, boxShadow: `0 0 10px ${r.color}66` }} />
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}

export default function FindingDetail() {
  const { scanId, findingId } = useParams()
  const { data: f, error, loading, reload } = useAsync(() => api.finding(scanId, findingId), [scanId, findingId])

  if (error) return <ErrorState error={error} onRetry={reload} />
  if (loading || !f) return <div className="space-y-4"><Skeleton className="h-28" /><Skeleton className="h-44" /><Skeleton className="h-96" /></div>

  const info = CWE_INFO[f.cwe]
  const entryLabel = f.call_path?.[0]?.endsWith('::__top_level__') ? 'App starts here' : 'Entry point'
  const routeLabel = f.reachability_status === 'reachable' && f.entry_point?.label ? f.entry_point.label : null
  const exploitable = f.reachability_status === 'reachable' && f.taint === 'user_input'
  const taintSteps = (f.taint_path_steps || []).length > 1 ? f.taint_path_steps : []

  return (
    <div>
      <Link to={`/scans/${scanId}`} className="inline-flex items-center gap-2 text-sm text-fog-400 hover:text-lime"><ArrowLeft size={15} /> Back to findings</Link>

      <header data-tour="finding-header" className="mt-6 animate-fade-up">
        <Label>{f.cwe} · {cweName(f.cwe)}</Label>
        <h1 className="mt-4 max-w-4xl font-display text-4xl font-light leading-tight tracking-tight text-fog-50 md:text-5xl">
          {f.title || cweName(f.cwe)} <span className="text-fade">in {prettyFn(f.function_name)}</span>
        </h1>
        <div className="mt-5 flex flex-wrap items-center gap-2">
          <RiskBadge category={f.risk_category} />
          <ReachBadge status={f.reachability_status} />
          <TaintBadge taint={f.taint} />
          <Pill>{SEVERITY_LABEL[f.severity] || f.severity} severity</Pill>
          <Pill>{f.detector === 'ai-model' ? 'AI model' : f.detector === 'semgrep' ? 'Semgrep' : 'Taint engine'}</Pill>
          <span className="font-mono text-xs text-fog-500">{f.file_path}:{f.line}</span>
        </div>
        <p className="mt-5 max-w-3xl text-[15px] leading-relaxed text-fog-300">{f.rule_message}</p>
      </header>

      {exploitable && (
        <div className="mt-8 flex items-center gap-3 rounded-2xl border border-risk-critical/30 bg-risk-critical/[0.07] px-5 py-4 text-sm text-[#ffb3b9]">
          <Crosshair size={18} className="shrink-0 text-risk-critical" />
          An attacker can reach this code through a live entry point, and user-controlled data was traced all the way to the dangerous call.
        </div>
      )}

      <section className="mt-10">
        <Card data-tour="attack-path" className="relative overflow-hidden p-6 md:p-8">
          <div className="pointer-events-none absolute -right-16 -top-16 h-48 w-48 rounded-full bg-risk-critical/10 blur-3xl" />
          <div className="flex flex-wrap items-center gap-3 text-fog-50">
            <Route size={16} className="text-risk-critical" /><Label>Attack path</Label>
            <InfoHint title="Attack path" learn="attack-path">The shortest chain of calls from where the app starts (or the route an attacker calls) to this vulnerable function.</InfoHint>
            {routeLabel && <Pill tone="danger">via {f.entry_point.kind === 'route' ? 'route' : f.entry_point.kind} {routeLabel}</Pill>}
          </div>
          <p className="mb-6 mt-2 text-sm text-fog-400">
            {f.reachability_status === 'reachable' ? 'Shortest call chain from an entry point to the vulnerable function.' :
              f.reachability_status === 'startup_only' ? 'Only reached while the application starts — no request handler leads here.' :
                'No entry point reaches this function, so it is ranked low even though the code is flawed.'}
          </p>
          <AttackPath steps={f.call_path_steps} entryLabel={entryLabel} variant="attack"
            emptyText="Dead code: this function is never called from server start-up, routes or other entry points." />
        </Card>
      </section>

      {taintSteps.length > 0 && (
        <section className="mt-6">
          <Card data-tour="data-flow" className="p-6 md:p-8">
            <div className="flex items-center gap-2"><Workflow size={16} className="text-lime" /><Label>Data flow</Label><InfoHint title="Data flow (taint)" learn="taint">Where attacker-controlled input enters and the functions it is passed through until it reaches the dangerous call.</InfoHint></div>
            <p className="mb-6 mt-2 text-sm text-fog-400">User input enters in the first function and is passed, argument by argument, into the sink.</p>
            <AttackPath steps={taintSteps} entryLabel="Input enters" variant="taint" />
          </Card>
        </section>
      )}

      <section className="mt-6 grid gap-6 lg:grid-cols-[1.6fr_1fr]">
        <div className="min-w-0" data-tour="code">
          <CodeView code={f.source_code} startLine={f.start_line || 1} highlightLines={f.related_lines?.length ? f.related_lines : [f.line]} file={`${f.file_path} · ${prettyFn(f.function_name)}`} />
          {f.snippet && <div className="mt-3 font-mono text-xs text-fog-500">sink: <span className="text-[#ff8a95]">{f.sink || f.snippet}</span></div>}
        </div>
        <div className="flex flex-col gap-6">
          <Breakdown f={f} />
          <Card className="p-6" data-tour="fix">
            <div className="flex items-center gap-2"><Lightbulb size={16} className="text-lime" /><Label>How to fix</Label></div>
            <p className="mt-4 text-sm leading-relaxed text-fog-300">{info ? info.fix : 'Review the function manually: the AI model considers it likely vulnerable but no specific rule identified the flaw.'}</p>
            {f.cwe && f.cwe !== 'CWE-Unknown' && (
              <a className="mt-4 inline-block text-xs text-lime hover:underline" href={`https://cwe.mitre.org/data/definitions/${f.cwe.replace('CWE-', '')}.html`} target="_blank" rel="noreferrer">
                Read {f.cwe} on cwe.mitre.org →
              </a>
            )}
          </Card>
          <Card className="p-6">
            <div className="flex items-center gap-2"><BrainCircuit size={16} className="text-lime" /><Label>AI signal</Label><InfoHint title="AI signal" learn="ai-model" align="right">How likely the machine-learning model thinks this function is vulnerable. It is one input (20%) to the score.</InfoHint></div>
            <div className="mt-4 flex items-baseline gap-3">
              <span className="font-display text-4xl font-light text-fog-50">{pct(f.vulnerability_probability)}</span>
              <span className="text-xs text-fog-500">{f.model_used}</span>
            </div>
            <p className="mt-2 text-xs leading-relaxed text-fog-500">Function-level probability from the classifier trained on 21,896 labeled JavaScript functions (JsVul). It contributes 20% of the score.</p>
          </Card>
          <Link to={`/scans/${scanId}/graph?focus=${encodeURIComponent(f.function_id || '')}`} className="btn-ghost"><Network size={15} /> Show in call graph</Link>
        </div>
      </section>
    </div>
  )
}
