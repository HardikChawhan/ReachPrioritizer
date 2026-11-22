import { BrainCircuit, Database, FlaskConical, Gauge, Network, Trophy } from 'lucide-react'
import { BarRow, Card, ErrorState, InfoHint, Label, PageHeader, Pill, Skeleton, StatTile, useAsync } from '../components/ui'
import { api } from '../lib/api'
import { cweName, pct } from '../lib/format'

const DETECTORS = {
  reachprioritizer_taint: 'ReachPrioritizer taint engine',
  ai_only_classifier: 'AI classifier only',
  v1_regex_rules: 'v1 prototype regex rules',
  eslint_plugin_security: 'ESLint plugin-security',
}

function MetricBars({ m }) {
  if (!m) return <div className="text-sm text-fog-500">No metrics recorded.</div>
  return (
    <div className="space-y-4">
      {[['F1', m.f1], ['Precision', m.precision], ['Recall', m.recall], ['ROC-AUC', m.roc_auc]].filter(([, v]) => v != null).map(([k, v]) => (
        <BarRow key={k} label={k} value={(v * 100).toFixed(1)} suffix="%" max={100} />
      ))}
    </div>
  )
}

function Evaluation() {
  const ev = useAsync(() => api.evaluation(), [])
  if (ev.loading) return <Skeleton className="h-96" />
  if (ev.error) return <ErrorState error={ev.error} onRetry={ev.reload} />
  const r = ev.data
  const s = r.summary || {}
  const det = s.detection_controlled_pooled || {}
  const prio = Object.entries(s.prioritization_mean || {})
  const best = prio.reduce((a, b) => ((b[1].average_precision ?? 0) > (a?.[1].average_precision ?? -1) ? b : a), null)
  const apps = [...(r.controlled || []), ...(r.realworld || [])]
  const rp = s.reachability_pooled || {}

  return (
    <div className="space-y-6">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <StatTile label="Detection F1" value={det.reachprioritizer_taint ? det.reachprioritizer_taint.f1.toFixed(2) : '–'} sub="controlled apps, function level" icon={FlaskConical} accent />
        <StatTile label="Real-world recall" value={s.detection_realworld_recall?.reachprioritizer_taint != null ? pct(s.detection_realworld_recall.reachprioritizer_taint) : '–'} sub="documented NodeGoat + DVNA flaws" icon={Trophy} />
        <StatTile label="Reachability acc." value={rp.accuracy != null ? pct(rp.accuracy) : '–'} sub={`${(rp.tp ?? 0) + (rp.tn ?? 0)} / ${(rp.tp ?? 0) + (rp.tn ?? 0) + (rp.fp ?? 0) + (rp.fn ?? 0)} labeled functions`} icon={Network} />
        <StatTile label="Ranking MAP" value={best ? best[1].average_precision?.toFixed(2) : '–'} sub={best ? best[1].name : ''} icon={Gauge} />
      </div>

      <Card className="p-6 md:p-8">
        <div className="flex items-center gap-2"><Label>Detection — who finds the real bugs?</Label><InfoHint title="Precision, recall, F1">Precision: how many reported issues are real. Recall: how many real issues were found. F1 combines both (1.00 is perfect).</InfoHint></div>
        <p className="mt-2 text-sm text-fog-400">Function-level precision / recall on the four fully-labeled controlled applications (pooled).</p>
        <div className="mt-6 overflow-x-auto">
          <table className="w-full min-w-[640px] text-sm">
            <thead><tr className="text-left font-mono text-[10px] uppercase tracking-[0.16em] text-fog-500">
              <th className="pb-3 font-normal">Detector</th><th className="pb-3 font-normal">TP</th><th className="pb-3 font-normal">FP</th><th className="pb-3 font-normal">FN</th><th className="pb-3 font-normal">Precision</th><th className="pb-3 font-normal">Recall</th><th className="w-1/4 pb-3 font-normal">F1</th>
            </tr></thead>
            <tbody>
              {Object.entries(det).map(([k, m]) => (
                <tr key={k} className={`border-t border-white/[0.05] ${k === 'reachprioritizer_taint' ? 'text-fog-50' : 'text-fog-300'}`}>
                  <td className="py-3 pr-4">{DETECTORS[k] || k}</td>
                  {m ? (<>
                    <td className="font-mono tabular-nums">{m.tp}</td><td className="font-mono tabular-nums">{m.fp}</td><td className="font-mono tabular-nums">{m.fn}</td>
                    <td className="font-mono tabular-nums">{m.precision.toFixed(2)}</td><td className="font-mono tabular-nums">{m.recall.toFixed(2)}</td>
                    <td><div className="flex items-center gap-3"><div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.05]"><div className="h-full rounded-full" style={{ width: `${m.f1 * 100}%`, background: k === 'reachprioritizer_taint' ? '#B4FF39' : '#687066' }} /></div><span className="w-10 font-mono text-xs tabular-nums">{m.f1.toFixed(2)}</span></div></td>
                  </>) : <td colSpan={6} className="text-fog-500">not installed</td>}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>

      <Card className="p-6 md:p-8">
        <div className="flex items-center gap-2"><Label>Prioritization — six ranking schemes</Label><InfoHint title="MAP, NDCG, P@1">P@1: is the #1 item truly exploitable? NDCG@5 and MAP reward rankings that put all exploitable bugs at the top (1.00 is perfect).</InfoHint></div>
        <p className="mt-2 text-sm text-fog-400">Same candidates, different scoring. Relevant = truly vulnerable <b className="font-medium text-fog-200">and</b> reachable. Mean over applications with exploitable bugs.</p>
        <div className="mt-6 grid gap-x-10 gap-y-5 md:grid-cols-2">
          {prio.map(([k, m]) => (
            <div key={k}>
              <div className="mb-2 flex items-center justify-between text-sm">
                <span className={k === 'E5_reachprioritizer' ? 'text-lime' : 'text-fog-300'}>{m.name}</span>
              </div>
              {[['MAP', m.average_precision], ['NDCG@5', m.ndcg_at_5], ['P@1', m.precision_at_1]].map(([lab, v]) => (
                <div key={lab} className="mb-1.5 flex items-center gap-3">
                  <span className="w-14 font-mono text-[10px] text-fog-500">{lab}</span>
                  <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-white/[0.05]"><div className="h-full rounded-full transition-all duration-700" style={{ width: `${(v || 0) * 100}%`, background: k === 'E5_reachprioritizer' ? '#B4FF39' : '#4A5148' }} /></div>
                  <span className="w-10 text-right font-mono text-xs tabular-nums text-fog-300">{v != null ? v.toFixed(2) : '–'}</span>
                </div>
              ))}
            </div>
          ))}
        </div>
      </Card>

      <Card className="p-6 md:p-8">
        <Label>Benchmarks</Label>
        <div className="mt-6 overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead><tr className="text-left font-mono text-[10px] uppercase tracking-[0.16em] text-fog-500">
              <th className="pb-3 font-normal">Application</th><th className="pb-3 font-normal">Functions</th><th className="pb-3 font-normal">Vulnerable</th><th className="pb-3 font-normal">Exploitable</th><th className="pb-3 font-normal">Detection</th><th className="pb-3 font-normal">Reachability</th><th className="pb-3 font-normal">Top-1 correct</th>
            </tr></thead>
            <tbody>
              {apps.map((a) => {
                const d = a.detection.reachprioritizer_taint
                const e5 = a.prioritization.E5_reachprioritizer
                return (
                  <tr key={a.application} className="border-t border-white/[0.05] text-fog-300">
                    <td className="py-3 pr-4 text-fog-50">{a.application}{a.repository && <Pill className="ml-2">real-world</Pill>}</td>
                    <td className="font-mono tabular-nums">{a.functions}</td>
                    <td className="font-mono tabular-nums">{a.labeled_vulnerable}</td>
                    <td className="font-mono tabular-nums">{a.exploitable}</td>
                    <td className="font-mono tabular-nums">{d.f1 != null ? `F1 ${d.f1.toFixed(2)}` : `recall ${d.recall.toFixed(2)}`}</td>
                    <td className="font-mono tabular-nums">{pct(a.reachability.accuracy)}</td>
                    <td>{a.exploitable ? (e5.precision_at_1 === 1 ? <span className="text-lime">yes</span> : <span className="text-risk-high">no</span>) : <span className="text-fog-600">n/a</span>}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
        <p className="mt-4 text-xs text-fog-500">Generated {new Date(r.generated_at).toLocaleString()} by evaluation/scripts/run_experiments.py · model {r.environment?.model_display}.</p>
      </Card>
    </div>
  )
}

export default function Research() {
  const m = useAsync(() => api.model(), [])
  const active = m.data?.active_model || {}
  const cks = m.data?.checkpoints || {}
  const ds = m.data?.dataset || {}

  return (
    <div>
      <PageHeader label="Model & research" title="The evidence" fade="behind every score." />

      <section className="mt-12 grid gap-6 lg:grid-cols-3">
        <Card data-tour="model" className="relative overflow-hidden p-6 lg:col-span-2">
          <div className="pointer-events-none absolute -right-20 -top-20 h-56 w-56 rounded-full bg-lime/10 blur-3xl" />
          <div className="flex items-center gap-2"><BrainCircuit size={16} className="text-lime" /><Label>Active AI model</Label><InfoHint title="Active AI model" learn="ai-model">The model that scores every function. The one with the best measured test F1 is selected automatically.</InfoHint></div>
          {m.loading ? <Skeleton className="mt-6 h-40" /> : m.error ? <div className="mt-6"><ErrorState error={m.error} onRetry={m.reload} /></div> : (
            <div className="mt-5 grid gap-8 md:grid-cols-2">
              <div>
                <div className="font-display text-3xl font-light text-fog-50">{active.display_name}</div>
                <div className="mt-2 text-sm text-fog-400">Selected by: {active.reason}. Decision threshold {active.threshold}.</div>
                <div className="mt-6 space-y-3">
                  {Object.entries(cks).map(([k, c]) => (
                    <div key={k} className="rounded-xl border border-white/[0.06] p-3">
                      <div className="flex items-center justify-between gap-2">
                        <span className="text-sm text-fog-100">{c.display_name}</span>
                        <Pill tone={k === active.model_name ? 'lime' : c.eligible ? 'muted' : 'warn'}>{k === active.model_name ? 'active' : c.eligible ? 'available' : 'not eligible'}</Pill>
                      </div>
                      <div className="mt-1 text-xs text-fog-500">
                        test F1 {c.test_metrics?.f1 != null ? c.test_metrics.f1.toFixed(3) : '–'}{c.note ? ` · ${c.note}` : ''}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
              <div>
                <div className="mb-4 font-mono text-[11px] uppercase tracking-[0.16em] text-fog-500">Held-out test split (2,081 functions)</div>
                <MetricBars m={active.test_metrics} />
                <p className="mt-5 text-xs leading-relaxed text-fog-500">The classifier is one signal (20% of the risk score). Concrete vulnerabilities come from the taint engine; train CodeBERT on a GPU with <span className="font-mono text-fog-300">ai/training/train_codebert.py</span> and it is used automatically if it scores better.</p>
              </div>
            </div>
          )}
        </Card>
        <Card className="p-6">
          <div className="flex items-center gap-2"><Database size={16} className="text-lime" /><Label>Training data</Label></div>
          {ds.total_samples ? (
            <>
              <div className="mt-5 font-display text-4xl font-light text-fog-50">{ds.total_samples.toLocaleString()}</div>
              <div className="text-sm text-fog-400">labeled JS functions · {ds.repositories?.toLocaleString()} repositories · {ds.unique_cves?.toLocaleString()} CVEs</div>
              <div className="mt-5 space-y-3">
                {['train', 'validation', 'test'].map((k) => ds.splits?.[k] && (
                  <BarRow key={k} label={k} value={ds.splits[k].total} max={ds.total_samples} sub={`${ds.splits[k].vuln_pct}% vulnerable`} color={k === 'train' ? '#B4FF39' : '#687066'} />
                ))}
              </div>
              <div className="mt-6 font-mono text-[11px] uppercase tracking-[0.16em] text-fog-500">Top CWEs in data</div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {(ds.top_cwes || []).slice(0, 8).map((c) => <Pill key={c.key} title={cweName(c.key)}>{c.key} · {c.count}</Pill>)}
              </div>
            </>
          ) : <Skeleton className="mt-6 h-48" />}
        </Card>
      </section>

      <section className="mt-16" data-tour="evaluation">
        <Label>Evaluation</Label>
        <h2 className="mb-8 mt-4 font-display text-4xl font-light text-fog-50">Measured, <span className="text-fade">not claimed.</span></h2>
        <Evaluation />
      </section>
    </div>
  )
}
