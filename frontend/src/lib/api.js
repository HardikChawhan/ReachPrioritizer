/** ReachPrioritizer API client (FastAPI backend under /api). */
const BASE = import.meta.env.VITE_API_BASE || '/api'

async function request(path, options = {}) {
  let res
  try {
    res = await fetch(`${BASE}${path}`, options)
  } catch {
    throw new Error('Cannot reach the ReachPrioritizer API. Is the backend running on port 8000?')
  }
  if (!res.ok) {
    let detail = res.statusText
    try {
      const j = await res.json()
      detail = typeof j.detail === 'string' ? j.detail : JSON.stringify(j.detail)
    } catch { /* not json */ }
    const err = new Error(detail || `Request failed (${res.status})`)
    err.status = res.status
    throw err
  }
  return res.json()
}

const json = (method, body) => ({ method, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })

export const api = {
  health: () => request('/health'),
  stats: () => request('/stats'),
  projects: () => request('/projects'),
  deleteProject: (id) => request(`/projects/${id}`, { method: 'DELETE' }),
  upload(file, name, onProgress, projectId = null) {
    // XHR for upload progress. With projectId: a new version of an existing project.
    return new Promise((resolve, reject) => {
      const fd = new FormData()
      fd.append('file', file)
      if (projectId) { if (name) fd.append('label', name) } else {
        if (name) fd.append('name', name)
        fd.append('auto_scan', 'true')
      }
      const xhr = new XMLHttpRequest()
      xhr.open('POST', projectId ? `${BASE}/projects/${projectId}/version` : `${BASE}/projects/upload`)
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress && onProgress(e.loaded / e.total)
      xhr.onload = () => {
        let body = {}
        try { body = JSON.parse(xhr.responseText) } catch { /* ignore */ }
        if (xhr.status >= 200 && xhr.status < 300) resolve(body)
        else reject(new Error(body.detail || `Upload failed (${xhr.status})`))
      }
      xhr.onerror = () => reject(new Error('Cannot reach the ReachPrioritizer API. Is the backend running on port 8000?'))
      xhr.send(fd)
    })
  },
  fromGithub: (url, branch, name) => request('/projects/from-github', json('POST', { url, branch: branch || null, name: name || null })),
  refreshGithub: (projectId) => request(`/projects/${projectId}/refresh`, { method: 'POST' }),
  project: (id) => request(`/projects/${id}`),
  trend: (projectId) => request(`/projects/${projectId}/trend`),
  previousScan: (id) => request(`/scans/${id}/previous`),
  compare: (baseId, headId) => request(`/scans/${baseId}/compare/${headId}`),
  startScan: (projectId) => request('/scans', json('POST', { project_id: projectId })),
  scans: (projectId) => request(`/scans${projectId ? `?project_id=${projectId}` : ''}`),
  scan: (id) => request(`/scans/${id}`),
  deleteScan: (id) => request(`/scans/${id}`, { method: 'DELETE' }),
  findings: (id, params = {}) => {
    const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== ''))
    return request(`/scans/${id}/findings${q.toString() ? `?${q}` : ''}`)
  },
  finding: (scanId, findingId) => request(`/scans/${scanId}/findings/${findingId}`),
  graph: (id, focus = 'all', includeModules = true) => request(`/scans/${id}/graph?focus=${focus}&include_modules=${includeModules}`),
  entryPoints: (id) => request(`/scans/${id}/entry-points`),
  exportUrl: (id, format) => `${BASE}/scans/${id}/export?format=${format}`,
  model: () => request('/model/status'),
  evaluation: () => request('/evaluation'),
}
