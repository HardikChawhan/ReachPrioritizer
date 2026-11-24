import { Component, Suspense, lazy, useEffect } from 'react'
import { BrowserRouter, Link, Route, Routes, useLocation } from 'react-router-dom'
import Layout from './components/Layout'
import { EmptyState, Spinner } from './components/ui'
import Dashboard from './pages/Dashboard'
import NewScan from './pages/NewScan'
import ScanResults from './pages/ScanResults'
import FindingDetail from './pages/FindingDetail'
import Scans from './pages/Scans'
import Research from './pages/Research'
import Learn from './pages/Learn'
import { TourProvider } from './tour/Tour'
import { Compass, TriangleAlert } from 'lucide-react'

const CallGraph = lazy(() => import('./pages/CallGraph'))
const Compare = lazy(() => import('./pages/Compare'))

class ErrorBoundary extends Component {
  constructor(props) { super(props); this.state = { error: null } }
  static getDerivedStateFromError(error) { return { error } }
  componentDidUpdate(prev) { if (prev.resetKey !== this.props.resetKey && this.state.error) this.setState({ error: null }) }
  render() {
    if (this.state.error) {
      return (
        <EmptyState icon={TriangleAlert} title="Something broke on this page" action={<button className="btn-ghost" onClick={() => window.location.reload()}>Reload</button>}>
          {String(this.state.error.message || this.state.error)}
        </EmptyState>
      )
    }
    return this.props.children
  }
}

function ScrollTop() {
  const { pathname } = useLocation()
  useEffect(() => { window.scrollTo({ top: 0 }) }, [pathname])
  return null
}

function Routed() {
  const loc = useLocation()
  return (
    <Layout>
      <ErrorBoundary resetKey={loc.pathname}>
        <Suspense fallback={<div className="flex h-[60vh] items-center justify-center"><Spinner size={28} /></div>}>
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/scan/new" element={<NewScan />} />
            <Route path="/upload" element={<NewScan />} />
            <Route path="/scans" element={<Scans />} />
            <Route path="/scans/:scanId" element={<ScanResults />} />
            <Route path="/scans/:scanId/findings/:findingId" element={<FindingDetail />} />
            <Route path="/scans/:scanId/graph" element={<CallGraph />} />
            <Route path="/compare" element={<Compare />} />
            <Route path="/research" element={<Research />} />
            <Route path="/model" element={<Research />} />
            <Route path="/learn" element={<Learn />} />
            <Route path="*" element={
              <EmptyState icon={Compass} title="Page not found" action={<Link to="/" className="btn-primary">Back to overview</Link>}>
                This page does not exist.
              </EmptyState>
            } />
          </Routes>
        </Suspense>
      </ErrorBoundary>
    </Layout>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <TourProvider>
        <ScrollTop />
        <Routed />
      </TourProvider>
    </BrowserRouter>
  )
}
