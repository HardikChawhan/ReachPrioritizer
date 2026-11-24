import { ExternalLink, Package, PhoneCall, Terminal } from 'lucide-react'
import { Card, InfoHint, Label, Pill } from './ui'
import { prettyFn } from '../lib/format'

const SEV_TONE = { critical: 'danger', high: 'danger', medium: 'warn', low: 'muted' }
const USAGE = {
  called: 'Your code calls this package',
  imported: 'Imported, but no call to it was found',
  unused: 'Listed in package.json but never imported',
}

export default function DependencyPanel({ dep }) {
  const upgrade = dep.fix_version ? `npm install ${dep.package}@${dep.fix_version}` : null
  const calls = (dep.usage || []).filter((u) => !u.import)
  return (
    <Card data-tour="dependency" className="p-6 md:p-8">
      <div className="flex flex-wrap items-center gap-3">
        <Package size={16} className="text-lime" />
        <Label>Vulnerable dependency</Label>
        <InfoHint title="Dependency check" learn="dependencies">
          The package version is looked up in OSV, Google's open vulnerability database. The call graph then tells whether your code really uses it from a reachable route — that decides the priority.
        </InfoHint>
        {dep.dev && <Pill>devDependency</Pill>}
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-[1fr_1.3fr]">
        <div>
          <div className="flex items-baseline gap-3">
            <span className="font-display text-3xl font-light text-fog-50">{dep.package}</span>
            <span className="font-mono text-lg text-[#ff8a95]">{dep.version}</span>
          </div>
          <div className="mt-1 text-xs text-fog-500">
            version from {dep.version_source === 'package-lock' ? 'package-lock.json (exact)' : `package.json "${dep.spec}" (lowest version the range allows)`} · {dep.manifest}
          </div>
          {upgrade && (
            <div className="mt-5 rounded-xl border border-lime/25 bg-lime/[0.05] p-4">
              <div className="flex items-center gap-2 text-sm text-fog-50"><Terminal size={14} className="text-lime" /> Fix: upgrade to <b className="font-mono text-lime">{dep.fix_version}</b> or later</div>
              <pre className="mt-2 overflow-x-auto rounded-lg bg-ink-950/70 px-3 py-2 font-mono text-xs text-fog-200">{upgrade}</pre>
            </div>
          )}
          <div className="mt-5">
            <div className="flex items-center gap-2 text-sm text-fog-200"><PhoneCall size={14} className="text-fog-400" />{USAGE[dep.usage_status]}</div>
            {dep.vulnerable_functions_called?.length > 0 && (
              <div className="mt-2 rounded-lg border border-risk-critical/30 bg-risk-critical/[0.06] px-3 py-2 text-xs text-[#ffb3b9]">
                Calls {dep.vulnerable_functions_called.map((x) => <code key={x} className="mx-0.5 font-mono">{x}()</code>)} — the function named in the advisory.
              </div>
            )}
            <ul className="mt-3 max-h-48 space-y-1.5 overflow-auto pr-1">
              {calls.slice(0, 12).map((u, i) => (
                <li key={i} className="flex items-center gap-2 rounded-lg border border-white/[0.05] px-3 py-1.5 font-mono text-[11px]">
                  <span className="truncate text-fog-200">{u.api}()</span>
                  <span className="text-fog-600">in</span>
                  <span className="truncate text-fog-400">{prettyFn((u.caller || '').split('::').pop())}</span>
                  <span className="flex-1" />
                  {u.user_input && <Pill tone="danger">user input</Pill>}
                  <span className="text-fog-600">{u.file}:{u.line}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>

        <div className="min-w-0">
          <div className="mb-2 font-mono text-[11px] uppercase tracking-[0.16em] text-fog-500">{dep.advisories.length} known advisor{dep.advisories.length === 1 ? 'y' : 'ies'}</div>
          <ul className="max-h-[420px] space-y-2 overflow-auto pr-1">
            {dep.advisories.map((a) => (
              <li key={a.id} className="rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3">
                <div className="flex flex-wrap items-center gap-2">
                  <Pill tone={SEV_TONE[a.severity] || 'muted'} dot>{a.severity}</Pill>
                  <span className="font-mono text-[11px] text-fog-300">{a.cve || a.id}</span>
                  {a.fixed && <span className="text-[11px] text-fog-500">fixed in {a.fixed}</span>}
                  <span className="flex-1" />
                  <a href={a.url} target="_blank" rel="noreferrer" className="text-fog-500 hover:text-lime" aria-label="Open advisory"><ExternalLink size={13} /></a>
                </div>
                <div className="mt-1.5 text-sm text-fog-200">{a.summary}</div>
              </li>
            ))}
          </ul>
        </div>
      </div>
    </Card>
  )
}
