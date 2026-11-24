import { useEffect, useMemo, useState } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  BookOpen, Compass, Crosshair, FileSearch, GitBranch, HelpCircle, LayoutDashboard, ListChecks, Network,
  Radar, Route, ShieldAlert, Sigma, Sparkles, Upload, Workflow, Swords, Package, GitCompareArrows, Github,
} from 'lucide-react'
import { Card, Label, PageHeader, Pill, ReachBadge, RiskBadge, RiskRing, TaintBadge } from '../components/ui'
import { useTour } from '../tour/Tour'
import { CWE_INFO, riskOf } from '../lib/format'

const SECTIONS = [
  ['what', 'What is ReachPrioritizer?'],
  ['pages', 'How to use the website'],
  ['entry-points', 'Entry points'],
  ['call-graph', 'Call graph'],
  ['reachability', 'Reachability'],
  ['taint', 'Taint / data flow'],
  ['attack-path', 'Attack path'],
  ['attack-sim', 'Attack simulator'],
  ['dependencies', 'Dependency check'],
  ['compare', 'Compare scans'],
  ['github', 'Scan from GitHub'],
  ['ai-model', 'The AI model'],
  ['risk-score', 'Risk score (try it)'],
  ['badges', 'Reading the badges'],
  ['vulnerabilities', 'Vulnerability types'],
  ['faq', 'FAQ'],
  ['glossary', 'Glossary'],
]

function Section({ id, icon: Icon, title, children }) {
  return (
    <section id={id} className="scroll-mt-28">
      <Card className="p-6 md:p-8">
        <div className="flex items-center gap-3">
          {Icon && <div className="rounded-xl border border-lime/20 bg-lime/[0.06] p-2.5 text-lime"><Icon size={17} /></div>}
          <h2 className="font-display text-2xl font-light text-fog-50 md:text-3xl">{title}</h2>
        </div>
        <div className="prose-rp mt-5 space-y-4 text-[15px] leading-relaxed text-fog-300">{children}</div>
      </Card>
    </section>
  )
}

function Code({ children }) {
  return <pre className="overflow-x-auto rounded-xl border border-white/[0.07] bg-ink-900/80 p-4 font-mono text-[12.5px] leading-6 text-fog-100">{children}</pre>
}

const PAGES = [
  { icon: LayoutDashboard, name: 'Overview', to: '/', text: 'The dashboard. Shows how many projects and scans exist, how many findings are actionable (reachable + user input proven), the overall risk mix and the most common weakness types. Recent scans are listed with their risk bar.' },
  { icon: Upload, name: 'New scan', to: '/scan/new', text: 'Upload a ZIP of a JavaScript / TypeScript / Node.js project. The archive is safety-checked, unpacked, analyzed and scored automatically, and you are taken to the results while it runs.' },
  { icon: ShieldAlert, name: 'Scan results', to: '/scans', text: 'The heart of the tool. Summary numbers, the risk distribution, the detected attack surface (routes) and the ranked list of findings with filters and search. Export as JSON, SARIF or CSV, or open the call graph.' },
  { icon: Route, name: 'Finding detail', text: 'Everything about one vulnerability: the attack path from an entry point, the data flow of user input, the highlighted code, a breakdown of the risk score, the AI signal and how to fix it.' },
  { icon: Network, name: 'Call graph', text: 'An interactive map of the whole program. Dots are functions, squares are files, lines are calls. Click a dot to highlight how execution gets there from an entry point.' },
  { icon: ListChecks, name: 'Scans', to: '/scans', text: 'All projects and all scans. Run a project again, or delete a scan or project together with its uploaded archive.' },
  { icon: Sparkles, name: 'Model & Research', to: '/research', text: 'The active AI model and its test metrics, the training dataset, and the evaluation results that compare ReachPrioritizer with other tools and ranking strategies.' },
]

function Calculator() {
  const [sev, setSev] = useState('high')
  const [taint, setTaint] = useState('user_input')
  const [ai, setAi] = useState(0.5)
  const [reach, setReach] = useState('reachable')
  const S = { critical: 1, high: 0.8, medium: 0.55, low: 0.3 }
  const E = { user_input: 1, parameter: 0.6, none: 0.35 }
  const M = { reachable: 1, startup_only: 0.4, unreachable: 0.2 }
  const score = useMemo(() => Math.round(100 * M[reach] * (0.45 * S[sev] + 0.35 * E[taint] + 0.2 * ai) * 10) / 10, [sev, taint, ai, reach])
  const Opt = ({ value, set, options }) => (
    <div className="flex flex-wrap gap-1.5">
      {options.map(([v, l]) => <button key={v} type="button" className={`chip ${value === v ? 'chip-active' : ''}`} onClick={() => set(v)}>{l}</button>)}
    </div>
  )
  return (
    <div className="grid gap-6 rounded-2xl border border-white/[0.07] bg-ink-900/60 p-5 md:grid-cols-[1fr_auto] md:items-center">
      <div className="space-y-4">
        <div><div className="mb-2 font-mono text-[10px] uppercase tracking-[0.16em] text-fog-500">Severity (45%)</div>
          <Opt value={sev} set={setSev} options={[['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']]} /></div>
        <div><div className="mb-2 font-mono text-[10px] uppercase tracking-[0.16em] text-fog-500">Exploitability / data flow (35%)</div>
          <Opt value={taint} set={setTaint} options={[['user_input', 'User input proven'], ['parameter', 'Parameter only'], ['none', 'No data flow']]} /></div>
        <div><div className="mb-2 font-mono text-[10px] uppercase tracking-[0.16em] text-fog-500">AI probability (20%) — {Math.round(ai * 100)}%</div>
          <input type="range" min="0" max="1" step="0.01" value={ai} onChange={(e) => setAi(Number(e.target.value))} className="w-full accent-[#B4FF39]" aria-label="AI probability" /></div>
        <div><div className="mb-2 font-mono text-[10px] uppercase tracking-[0.16em] text-fog-500">Reachability (multiplier)</div>
          <Opt value={reach} set={setReach} options={[['reachable', 'Reachable ×1.0'], ['startup_only', 'Startup only ×0.4'], ['unreachable', 'Dead code ×0.2']]} /></div>
      </div>
      <div className="flex flex-col items-center gap-3 md:px-6">
        <RiskRing score={score} size={120} stroke={8} showLabel />
        <RiskBadge category={riskOf(score)} />
      </div>
    </div>
  )
}

const FAQ = [
  ['Is my code executed or sent anywhere?', 'No. The code is only parsed into a syntax tree on the machine running the backend; nothing is executed. The only outside call is the dependency check, which sends package names and versions (not code) to osv.dev. Set RP_ENABLE_DEPCHECK=0 to turn it off.'],
  ['Does the attack simulator attack my app?', 'No. It only writes down the request an attacker would send and shows, step by step, how the payload would travel. Nothing is sent. You can copy the request and try it against your own local copy.'],
  ['Which languages and frameworks are supported?', 'JavaScript and TypeScript (.js .mjs .cjs .jsx .ts .tsx). Entry points are recognized for Express, Koa, Fastify, hapi, Node http/https servers, serverless handlers and Next.js API routes.'],
  ['Why does a "critical" vulnerability get a low score?', 'Because nothing can reach it: no route or start-up code ever calls that function (dead code), or it only runs while the application boots. It is still listed, so it can be cleaned up, but after the reachable issues.'],
  ['What does "AI only" mean?', 'The machine-learning model thinks the function looks vulnerable (≥ 85% probability), but no rule found a concrete flow from input to a dangerous call. Treat it as a hint for manual review.'],
  ['Can it miss vulnerabilities or report false ones?', 'Yes. Static analysis has limits: very dynamic JavaScript (computed method names, dependency-injection containers, generated code) can hide calls, and template-level XSS, login / permission logic and vulnerable npm packages are out of scope. The evaluation page shows how it performs on labeled benchmarks.'],
  ['What is SARIF?', 'A standard JSON format for static-analysis results. Upload it to GitHub code scanning or open it in VS Code (SARIF Viewer) to see the findings inline in the code.'],
  ['Why is a route shown as "inactive"?', 'The route is registered in a file or function that never runs, for example a router module nobody imports. An attacker cannot call it.'],
  ['Does it analyze node_modules?', 'No. Third-party packages are skipped to keep scans fast and focused on your code. Use a dependency scanner (npm audit, Dependabot) for vulnerable package versions.'],
]

const GLOSSARY = [
  ['AST', 'Abstract Syntax Tree — the program parsed into a tree structure the analyzer can walk.'],
  ['Call graph', 'A graph of which function calls which.'],
  ['CVE', 'Common Vulnerabilities and Exposures — the public ID of one specific known bug in one product (e.g. CVE-2021-23337 in lodash).'],
  ['OSV', 'Open Source Vulnerabilities — a free database by Google that maps package versions to known CVEs / advisories.'],
  ['Payload', 'The malicious value an attacker puts into a request, e.g. \' OR \'1\'=\'1 for SQL injection.'],
  ['CWE', 'Common Weakness Enumeration — a standard ID for a type of vulnerability (e.g. CWE-89 = SQL injection).'],
  ['Entry point', 'Where execution starts: server start-up code, or a route handler that receives requests.'],
  ['Exploitable', 'Reachable from an entry point AND fed with attacker-controlled data.'],
  ['False positive', 'A reported issue that is not actually a vulnerability.'],
  ['Sanitizer', 'A function that makes input safe for a specific use (escaping, parsing to a number, taking a file basename, ...).'],
  ['Sink', 'A dangerous operation: running a shell command, a SQL query, eval, reading a file path, making an HTTP request, ...'],
  ['Source', 'Where attacker-controlled data comes from: request body, query string, URL parameters, headers, cookies.'],
  ['Static analysis', 'Analyzing code without running it.'],
  ['Taint', 'The "this value came from the user" label that is followed through the program.'],
  ['TF-IDF', 'A classic text-mining technique that weights how characteristic each token is; used by the default AI model.'],
  ['CodeBERT', 'A transformer neural network pre-trained on source code; can be fine-tuned on a GPU for better accuracy.'],
]

export default function Learn() {
  const { start } = useTour()
  const loc = useLocation()
  const [activeId, setActiveId] = useState('what')

  useEffect(() => {
    if (loc.hash) {
      const el = document.getElementById(loc.hash.slice(1))
      if (el) setTimeout(() => el.scrollIntoView({ behavior: 'smooth', block: 'start' }), 80)
    }
  }, [loc.hash])

  useEffect(() => {
    const obs = new IntersectionObserver((entries) => {
      const vis = entries.filter((e) => e.isIntersecting).sort((a, b) => a.boundingClientRect.top - b.boundingClientRect.top)
      if (vis[0]) setActiveId(vis[0].target.id)
    }, { rootMargin: '-120px 0px -60% 0px' })
    SECTIONS.forEach(([id]) => { const el = document.getElementById(id); if (el) obs.observe(el) })
    return () => obs.disconnect()
  }, [])

  return (
    <div>
      <PageHeader label="Learn" title="Everything explained," fade="in plain words.">
        <button className="btn-primary" onClick={start}><Compass size={15} /> Take the guided tour</button>
      </PageHeader>

      <div className="mt-12 grid gap-8 lg:grid-cols-[240px_1fr]">
        <nav data-tour="learn-toc" className="lg:sticky lg:top-28 lg:self-start">
          <Card className="p-3">
            {SECTIONS.map(([id, title]) => (
              <a key={id} href={`#${id}`} onClick={(e) => { e.preventDefault(); document.getElementById(id)?.scrollIntoView({ behavior: 'smooth' }); window.history.replaceState(null, '', `#${id}`) }}
                className={`block rounded-lg px-3 py-2 text-sm transition ${activeId === id ? 'bg-lime/10 text-lime' : 'text-fog-400 hover:bg-white/[0.03] hover:text-fog-100'}`}>
                {title}
              </a>
            ))}
          </Card>
        </nav>

        <div className="min-w-0 space-y-6">
          <Section id="what" icon={BookOpen} title="What is ReachPrioritizer?">
            <p>Security scanners usually produce a long list of "possible vulnerabilities". Many of them can never be attacked: the code is never called (dead code), it only runs while the app starts, or it never receives data from a user. Developers waste time on these and miss the dangerous ones.</p>
            <p><b className="font-medium text-fog-50">ReachPrioritizer answers one question: which vulnerabilities can an attacker actually reach?</b> It reads your project's code (without running it), finds where requests come in, follows the calls and the user's data through the program, and ranks every finding with an explainable score.</p>
            <div className="grid gap-3 sm:grid-cols-3">
              {[[FileSearch, 'Understand the code', 'Parse every file and build a map of all function calls.'], [Crosshair, 'Find what is exposed', 'Detect the routes and handlers an attacker can call, and what they lead to.'], [Radar, 'Rank by real risk', 'Severity × proof of user input × AI × reachability = one score.']].map(([I, t, d]) => (
                <div key={t} className="rounded-xl border border-white/[0.06] p-4"><I size={16} className="text-lime" /><div className="mt-2 text-fog-50">{t}</div><div className="mt-1 text-sm text-fog-400">{d}</div></div>
              ))}
            </div>
          </Section>

          <Section id="pages" icon={Compass} title="How to use the website">
            <p>A typical session: <b className="font-medium text-fog-50">New scan</b> → upload a ZIP → wait a few seconds → read the <b className="font-medium text-fog-50">ranked findings</b> top-down → open a finding to see its <b className="font-medium text-fog-50">attack path</b> and fix advice → export SARIF for your team.</p>
            <div className="grid gap-3 md:grid-cols-2">
              {PAGES.map((p) => (
                <div key={p.name} className="rounded-xl border border-white/[0.06] p-4">
                  <div className="flex items-center gap-2"><p.icon size={15} className="text-lime" /><span className="text-fog-50">{p.name}</span>{p.to && <Link to={p.to} className="ml-auto text-xs text-lime hover:underline">Open →</Link>}</div>
                  <p className="mt-2 text-sm text-fog-400">{p.text}</p>
                </div>
              ))}
            </div>
            <p className="text-sm">Tip: every important panel has a small <span className="inline-flex h-5 w-5 items-center justify-center rounded-full border border-white/15 text-[10px] text-fog-300">?</span> button that explains it in place.</p>
          </Section>

          <Section id="entry-points" icon={Crosshair} title="Entry points">
            <p>An <b className="font-medium text-fog-50">entry point</b> is where execution begins. ReachPrioritizer distinguishes two kinds:</p>
            <ul className="list-disc space-y-1 pl-5">
              <li><b className="font-medium text-fog-50">Startup roots</b> — code that runs when the application starts: the file that calls <code className="text-lime">app.listen()</code> or <code className="text-lime">http.createServer()</code>, the <code>main</code> / <code>start</code> script in package.json, or <code>require.main === module</code>.</li>
              <li><b className="font-medium text-fog-50">Request roots</b> — functions that handle incoming requests: <code>app.get('/users', handler)</code>, <code>router.post(...)</code>, Fastify/hapi routes, server request callbacks, serverless handlers and Next.js API routes. These are what an attacker talks to.</li>
            </ul>
            <p>A route only counts as <b className="font-medium text-fog-50">active</b> if the code that registers it actually runs. A router file that nobody imports is listed as inactive.</p>
            <Code>{`const app = express()            // startup root: app.js runs at start
app.use('/api/users', userRoutes) // loads routes/userRoutes.js
router.get('/:id', ctrl.getUser)  // request root: GET /api/users/:id
app.listen(3000)`}</Code>
          </Section>

          <Section id="call-graph" icon={GitBranch} title="Call graph">
            <p>The call graph is a map of <i>which function calls which</i>, across all files. ReachPrioritizer understands imports (<code>require</code> / <code>import</code>), exported objects and classes, <code>this.method()</code>, objects created with <code>new</code>, routers, and functions passed as callbacks.</p>
            <p>On the <b className="font-medium text-fog-50">Call graph</b> page every dot is a function, every square is a file (module) and every arrow is a call. Dashed lines mean "this file loads that file".</p>
          </Section>

          <Section id="reachability" icon={Network} title="Reachability">
            <p>For every function the analyzer searches the call graph from the entry points and gives it one of three statuses:</p>
            <div className="space-y-3">
              <div className="flex flex-wrap items-center gap-3"><ReachBadge status="reachable" /><span>An attacker request can make this function run (there is a path from an active route or request handler).</span></div>
              <div className="flex flex-wrap items-center gap-3"><ReachBadge status="startup_only" /><span>It runs only while the app starts (configuration, scheduled jobs). Requests cannot trigger it.</span></div>
              <div className="flex flex-wrap items-center gap-3"><ReachBadge status="unreachable" /><span>Nothing ever calls it: abandoned or legacy code.</span></div>
            </div>
            <p>Reachability is the biggest factor in the ranking: dead code is multiplied by 0.2, startup-only code by 0.4.</p>
          </Section>

          <Section id="taint" icon={Workflow} title="Taint / data flow">
            <p><b className="font-medium text-fog-50">Taint tracking</b> follows data that comes from the user. A value is "tainted" when it comes from a <b className="font-medium text-fog-50">source</b> (<code>req.query</code>, <code>req.body</code>, <code>req.params</code>, headers, cookies, ...). The taint travels through variables, string building and function calls, even across files. If it reaches a <b className="font-medium text-fog-50">sink</b> (a dangerous operation) without passing a <b className="font-medium text-fog-50">sanitizer</b>, it is a vulnerability.</p>
            <Code>{`// routes/files.js
function executeCommand(req, res) {
  const cmd = req.query.cmd          // SOURCE: attacker controls ?cmd=
  res.json(executeCmd(cmd))          // passed to another function
}
// controllers/fileController.js
function runCommand(cmd) {
  execSync('ls ' + cmd)              // SINK: shell command -> command injection
}`}</Code>
            <p>Safe patterns are recognized too: parameterized SQL queries, <code>path.basename()</code>, HTML escaping, <code>parseInt()</code>, and guard clauses such as <code>{'if (!ALLOWED.includes(cmd)) return'}</code>.</p>
            <div className="flex flex-wrap gap-2"><TaintBadge taint="user_input" /><TaintBadge taint="parameter" /><TaintBadge taint="none" /><TaintBadge taint="unknown" /></div>
          </Section>

          <Section id="attack-path" icon={Route} title="Attack path">
            <p>For a reachable finding, the <b className="font-medium text-fog-50">attack path</b> is the shortest chain of calls from where the application starts, through the route the attacker calls, down to the vulnerable function. It answers "how would someone get here?" and shows exactly which route to protect or test.</p>
            <Code>{`app.js (module load)  →  setupFileRoutes  →  GET /execute: executeCommand  →  executeCmd  →  runCommand  ☠`}</Code>
          </Section>

          <Section id="attack-sim" icon={Swords} title="Attack simulator">
            <p>For every finding where user input reaches the bug, ReachPrioritizer writes the <b className="font-medium text-fog-50">exact request an attacker would send</b> — as curl, JavaScript fetch and raw HTTP — and plays the attack step by step: the request arrives, the route handler reads the input, the value is passed from function to function, and it lands in the dangerous line.</p>
            <p>The last step shows <b className="font-medium text-fog-50">what the server would really execute</b>, with the attacker's part highlighted. Everything comes from what the engine proved: the full URL (router mount prefixes included), the input field (for example <code>req.query.file</code>) and the code around the sink.</p>
            <Code>{`curl -i -X POST -H 'Content-Type: application/json' --data '{"term": "' OR '1'='1' -- "}' http://localhost:3005/api/users/search

→ SELECT id, name FROM users WHERE name LIKE '%' OR '1'='1' -- %'`}</Code>
            <p>It is a <b className="font-medium text-fog-50">simulation</b>: nothing is ever sent or executed. The verdict says whether the request would really work today (<i>exploitable</i>), only at startup (<i>internal</i>), or never because no route leads there (<i>blocked</i>). Only test the request against your own local copy.</p>
          </Section>

          <Section id="dependencies" icon={Package} title="Dependency check">
            <p>Most real attacks come through outdated npm packages. ReachPrioritizer reads <code>package.json</code> (and <code>package-lock.json</code> for exact versions) and asks <b className="font-medium text-fog-50">OSV</b>, Google's open vulnerability database, which versions have known CVEs.</p>
            <p>Then comes the part other tools skip: the call graph shows <b className="font-medium text-fog-50">whether your code actually calls the package from a reachable route</b>, whether user input is passed in, and whether it calls the very function named in the advisory (for example <code>lodash.template</code>). A package that is listed but never imported is ranked low; one called from a live route with request data is ranked critical.</p>
            <p>Only package names and versions are sent to osv.dev — never your code. Without internet the check is skipped and the rest of the scan works normally.</p>
          </Section>

          <Section id="compare" icon={GitCompareArrows} title="Compare scans">
            <p>Scan a project, fix some bugs, then scan the <b className="font-medium text-fog-50">new version</b> (upload a new ZIP or pull the latest commit from GitHub). The Compare page matches findings by function and weakness type and sorts them into <span className="text-lime">Fixed</span>, <span className="text-[#ff8a95]">New</span> and <span className="text-[#ffb27a]">Still open</span>.</p>
            <p>Both call graphs are drawn <b className="font-medium text-fog-50">side by side</b>. Select a finding and its attack path lights up in both versions, so you can see that a path was cut, moved or newly opened. It also lists new or removed routes, functions that became reachable, and a trend chart across all scans of the project.</p>
          </Section>

          <Section id="github" icon={Github} title="Scan from GitHub">
            <p>Paste a public repository link such as <code>https://github.com/OWASP/NodeGoat</code> (optionally a branch or tag). The backend downloads the repository archive from GitHub, applies the same safety checks as a ZIP upload, and scans it. The commit id is recorded, and "New version" pulls the latest commit for a before/after comparison.</p>
          </Section>

          <Section id="ai-model" icon={Sparkles} title="The AI model">
            <p>A machine-learning classifier reads each function and estimates how likely it is to be vulnerable. It was trained on <b className="font-medium text-fog-50">21,896 real JavaScript functions</b> taken from security-fix commits in 1,164 GitHub repositories (the JsVul dataset), with train / validation / test repositories kept separate.</p>
            <p>The default model is TF-IDF + Logistic Regression (fast, CPU). A CodeBERT neural network can be trained on a GPU and is used automatically if it scores better. The AI is <b className="font-medium text-fog-50">one signal (20%)</b>: concrete vulnerabilities come from the taint engine. Functions the AI rates ≥ 85% without any rule match appear as "AI only" suggestions.</p>
          </Section>

          <Section id="risk-score" icon={Sigma} title="Risk score — try it">
            <p className="font-mono text-sm text-fog-100">risk = 100 × reachability × (0.45 · severity + 0.35 · exploitability + 0.20 · AI)</p>
            <p>Change the inputs to see how the score reacts. Notice how a critical issue in dead code ends up Low, while a medium issue with proven user input in reachable code stays High.</p>
            <Calculator />
            <div className="flex flex-wrap gap-2"><RiskBadge category="Critical" /><span className="text-sm">≥ 70</span><RiskBadge category="High" /><span className="text-sm">45–70</span><RiskBadge category="Medium" /><span className="text-sm">25–45</span><RiskBadge category="Low" /><span className="text-sm">&lt; 25</span></div>
          </Section>

          <Section id="badges" icon={ListChecks} title="Reading the badges">
            <div className="grid gap-x-8 gap-y-3 md:grid-cols-2">
              {[
                [<ReachBadge key="a" status="reachable" />, 'Reachable from a live route / request handler.'],
                [<ReachBadge key="b" status="startup_only" />, 'Runs only when the app starts.'],
                [<ReachBadge key="c" status="unreachable" />, 'Never called (dead code).'],
                [<TaintBadge key="d" taint="user_input" />, 'User input proven to reach the dangerous call.'],
                [<TaintBadge key="e" taint="parameter" />, 'A function parameter reaches it; no caller passes user input (yet).'],
                [<TaintBadge key="f" taint="none" />, 'An issue without data flow, e.g. a hardcoded password.'],
                [<TaintBadge key="g" taint="unknown" />, 'Only the AI model flagged it.'],
                [<Pill key="h">Taint engine</Pill>, 'Which detector produced the finding (taint engine, Semgrep, AI model).'],
              ].map(([b, t], i) => <div key={i} className="flex items-start gap-3 text-sm"><span className="shrink-0">{b}</span><span>{t}</span></div>)}
            </div>
          </Section>

          <Section id="vulnerabilities" icon={ShieldAlert} title="Vulnerability types (CWE)">
            <div className="grid gap-3 md:grid-cols-2">
              {Object.entries(CWE_INFO).map(([cwe, info]) => (
                <div key={cwe} className="rounded-xl border border-white/[0.06] p-4">
                  <div className="flex items-center justify-between gap-2"><span className="text-fog-50">{info.name}</span><span className="font-mono text-[11px] text-fog-500">{cwe}</span></div>
                  <p className="mt-2 text-sm text-fog-400"><span className="text-lime">Fix: </span>{info.fix}</p>
                </div>
              ))}
            </div>
          </Section>

          <Section id="faq" icon={HelpCircle} title="FAQ">
            <div className="divide-y divide-white/[0.06]">
              {FAQ.map(([q, a]) => (
                <details key={q} className="group py-3">
                  <summary className="cursor-pointer list-none text-fog-50 marker:hidden">
                    <span className="mr-2 inline-block text-lime transition-transform group-open:rotate-90">›</span>{q}
                  </summary>
                  <p className="mt-2 pl-5 text-sm text-fog-400">{a}</p>
                </details>
              ))}
            </div>
          </Section>

          <Section id="glossary" icon={BookOpen} title="Glossary">
            <dl className="grid gap-x-8 gap-y-3 md:grid-cols-2">
              {GLOSSARY.map(([t, d]) => (
                <div key={t}><dt className="font-mono text-sm text-lime">{t}</dt><dd className="text-sm text-fog-400">{d}</dd></div>
              ))}
            </dl>
          </Section>
        </div>
      </div>
    </div>
  )
}
