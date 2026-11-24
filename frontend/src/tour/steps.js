/**
 * Guided tour script. Each step points at an element marked with data-tour="<target>".
 * route: a path, or a function of the tour context that returns a path (or null to skip).
 * optional: skip silently when the target is not on the page.
 */
export function buildSteps(ctx) {
  const scan = ctx.scanId ? `/scans/${ctx.scanId}` : null
  const finding = ctx.scanId && ctx.findingId ? `/scans/${ctx.scanId}/findings/${ctx.findingId}` : null
  const graph = ctx.scanId ? `/scans/${ctx.scanId}/graph` : null

  const steps = [
    {
      route: '/', target: null,
      title: 'Welcome to ReachPrioritizer',
      body: 'Security scanners report hundreds of issues. This tool finds which of them an attacker can actually reach, and puts those first. This 2-minute tour walks you through every page. Use the arrow keys or the buttons below, and press Esc to leave at any time.',
    },
    {
      route: '/', target: 'nav',
      title: 'Main navigation',
      body: 'Overview is this dashboard. Scans lists every project and scan. Model & Research shows the AI model and the measured evaluation. Learn is the built-in guide that explains every concept.',
    },
    {
      route: '/', target: 'new-scan',
      title: 'Start a new scan',
      body: 'Upload a ZIP of any JavaScript / TypeScript / Node.js project here. The tour opens this page in a moment.',
    },
    {
      route: '/', target: 'stats', optional: true,
      title: 'Portfolio at a glance',
      body: '"Actionable" counts findings that are reachable from a live route and where user input is proven to reach the dangerous code. These are the ones to fix first. "Deprioritized" counts issues in dead or startup-only code.',
    },
    {
      route: '/', target: 'recent-scans', optional: true,
      title: 'Recent scans',
      body: 'Each row is the latest scan of a project. The coloured bar is its risk mix (red = Critical, orange = High, yellow = Medium, blue = Low). Click a row to open the results.',
    },
    {
      route: '/', target: 'insights', optional: true,
      title: 'Risk mix & top weaknesses',
      body: 'How findings across your projects split by risk category, and which weakness types (CWE) appear most often.',
    },
    {
      route: '/scan/new', target: 'dropzone',
      title: 'Upload a project',
      body: 'Drag a .zip here (up to 100 MB). node_modules, tests and build files are skipped automatically. Code is only parsed, never executed. The scan starts immediately and usually takes a few seconds.',
    },
    {
      route: '/scan/new', target: 'github-tab', optional: true,
      title: 'Or paste a GitHub link',
      body: 'No ZIP needed: paste the link of a public GitHub repository (for example github.com/OWASP/NodeGoat) and an optional branch. The repository is downloaded with the same safety checks and scanned straight away.',
    },
    {
      route: '/scan/new', target: 'scan-info', optional: true,
      title: 'What gets analyzed',
      body: 'Supported languages and frameworks, plus the safety checks run on every archive before it is unpacked.',
    },
  ]

  if (!scan) {
    steps.push({
      route: '/scan/new', target: 'dropzone',
      title: 'Scan something to unlock the rest of the tour',
      body: 'There are no completed scans yet. Upload test-applications/express-app.zip from the repository (or paste a GitHub link), then start the tour again from the "Tour" button to see the results, the attack paths and the call graph.',
    })
  } else {
    steps.push(
      {
        route: scan, target: 'scan-actions',
        title: 'A scan result',
        body: 'This is the latest completed scan. Use these buttons to open the interactive call graph, export the report (JSON, SARIF for GitHub code scanning, or CSV), or run the scan again.',
      },
      {
        route: scan, target: 'scan-stats',
        title: 'The four numbers that matter',
        body: 'Actionable = reachable + user input proven. Findings = everything detected. Deprioritized = the share of findings in dead or startup-only code. Code analyzed = the size of the call graph.',
      },
      {
        route: scan, target: 'attack-strip', optional: true,
        title: 'Attack simulations',
        body: 'How many findings come with a ready-made attack: the exact request an attacker would send and a step-by-step replay. Click to show only the findings where user input reaches the bug.',
      },
      {
        route: scan, target: 'deps-strip', optional: true,
        title: 'Dependency check',
        body: 'Your npm packages are checked against the public OSV vulnerability database, and the call graph tells whether your code actually uses the vulnerable package from a reachable route. Click to list only dependency findings.',
      },
      {
        route: scan, target: 'compare-btn', optional: true,
        title: 'Compare with the previous scan',
        body: 'After you fix something, scan the new version ("New version" button) and compare: fixed, new and still-open findings, with both call graphs side by side.',
      },
      {
        route: scan, target: 'risk-dist',
        title: 'Risk distribution',
        body: 'Every finding gets a risk score from 0 to 100 and a category. Click a category tile to filter the list below. The bottom row shows where the findings live: reachable code, startup-only code or dead code.',
      },
      {
        route: scan, target: 'attack-surface',
        title: 'Attack surface',
        body: 'All entry points the analyzer detected: HTTP routes, server handlers and so on. Faded "inactive" routes are registered in code that never runs (for example a router file nobody imports), so they cannot be attacked.',
      },
      {
        route: scan, target: 'filters',
        title: 'Search, sort and filter',
        body: 'Combine filters by risk, reachability and data flow, or search by file, function or CWE. The list is already sorted by risk, so the first item is the one to fix first.',
      },
      {
        route: scan, target: 'findings',
        title: 'Prioritized findings',
        body: 'Each row shows the risk score ring, the vulnerability type, where it is (function · file:line), and badges for reachability and data flow. Click a finding to see why it matters.',
      },
    )
    if (finding) {
      steps.push(
        {
          route: finding, target: 'finding-header',
          title: 'Finding detail',
          body: 'The vulnerability type (with its CWE id), the location, and badges: risk category, reachability, data flow, severity and which detector found it. The sentence below explains the problem in plain words.',
        },
        {
          route: finding, target: 'attack-sim', optional: true,
          title: 'Attack simulator',
          body: 'The request an attacker would send (copy it as curl, JavaScript or raw HTTP) and a replay of the attack: press "Replay attack" to watch the payload travel from the route to the dangerous line, and see the exact query or command the server would run. It is only a simulation — nothing is sent.',
        },
        {
          route: finding, target: 'attack-path',
          title: 'Attack path',
          body: 'The chain of function calls from where the application starts (or the route an attacker calls) down to the vulnerable code. If no path exists the function is dead code, and it is ranked low.',
        },
        {
          route: finding, target: 'data-flow', optional: true,
          title: 'Data flow (taint)',
          body: 'Where user input enters (for example a route handler that reads req.query) and the functions it travels through until it reaches the dangerous call.',
        },
        {
          route: finding, target: 'code',
          title: 'The code',
          body: 'The vulnerable function. The highlighted red lines are where the dangerous call happens.',
        },
        {
          route: finding, target: 'score',
          title: 'Why this score',
          body: 'The score is explainable: severity (45%), exploitability, i.e. whether user input is proven to reach the sink (35%), and the AI probability (20%), all multiplied by reachability (×1.0 reachable, ×0.4 startup-only, ×0.2 dead code).',
        },
        {
          route: finding, target: 'fix',
          title: 'How to fix it',
          body: 'A concrete remediation for this vulnerability type, with a link to the official CWE description.',
        },
      )
    }
    steps.push(
      {
        route: graph, target: 'graph-controls',
        title: 'Interactive call graph',
        body: 'Every dot is a function, every square a file, every line a call. "Live code" hides dead code; "Attack paths" keeps only the functions that lead to findings. Use the search box to jump to a function.',
      },
      {
        route: graph, target: 'graph-legend', optional: true,
        title: 'Reading the colours',
        body: 'Lime = entry point, red = vulnerable and reachable, dark red = vulnerable but dead/startup-only, white = reachable code, grey = dead code. Click any dot to light up the path from an entry point to it.',
      },
    )
  }

  steps.push(
    {
      route: '/research', target: 'model',
      title: 'The AI model',
      body: 'Which machine-learning model is active, how it scored on 2,081 held-out functions, and the dataset it was trained on (21,896 real JavaScript functions from security fixes).',
    },
    {
      route: '/research', target: 'evaluation',
      title: 'Measured, not claimed',
      body: 'Results of the evaluation script: detection compared with other tools, reachability accuracy, and how six ranking strategies compare. Everything is regenerated by evaluation/scripts/run_experiments.py.',
    },
    {
      route: '/learn', target: 'learn-toc',
      title: 'Learn more anytime',
      body: 'The Learn page explains every concept (entry points, reachability, taint, the risk score, each vulnerability type) with examples. Restart this tour any time with the "Tour" button at the top. Happy hunting!',
    },
  )
  return steps
}
