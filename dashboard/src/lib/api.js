const BASE = '/api/v1'

async function req(method, path, body) {
  const opts = { method, headers: { 'Content-Type': 'application/json' } }
  if (body) opts.body = JSON.stringify(body)
  let res
  try {
    res = await fetch(BASE + path, opts)
  } catch (networkError) {
    const error = new Error('BountyOS backend is unavailable or the network request failed.')
    error.code = 'backend_unavailable'
    error.retryable = true
    error.cause = networkError
    throw error
  }
  if (!res.ok) {
    const payload = await res.json().catch(() => ({ detail: res.statusText }))
    const detail = payload?.detail
    const message = typeof detail === 'string'
      ? detail
      : detail?.message || payload?.message || res.statusText || `HTTP ${res.status}`
    const error = new Error(message)
    error.status = res.status
    error.payload = payload
    error.code = detail?.code || payload?.code || 'api_error'
    error.retryable = Boolean(detail?.retryable || payload?.retryable)
    error.retryAfterSeconds = detail?.retry_after_seconds || payload?.retry_after_seconds || null
    throw error
  }
  if (res.status === 204) return null
  return res.json()
}

export const api = {
  targets:   {
    list:   ()         => req('GET',    '/targets/'),
    get:    id         => req('GET',    `/targets/${id}`),
    create: data       => req('POST',   '/targets/', data),
    update: (id, data) => req('PATCH',  `/targets/${id}`, data),
    delete: id         => req('DELETE', `/targets/${id}`),
  },
  scans: {
    list:     ()               => req('GET',  '/scans/'),
    get:      id               => req('GET',  `/scans/${id}`),
    create:   data             => req('POST', '/scans/', data),
    cancel:   id               => req('POST', `/scans/${id}/cancel`),
    events:   (id, lvl)        => req('GET',  `/scans/${id}/events${lvl?`?level=${lvl}`:''}`),
    findings: id               => req('GET',  `/scans/${id}/findings`),
  },
  findings: {
    list:   sev        => req('GET',    `/findings/${sev?`?severity=${sev}`:''}`),
    get:    id         => req('GET',    `/findings/${id}`),
    update: (id, data) => req('PATCH',  `/findings/${id}`, data),
    delete: id         => req('DELETE', `/findings/${id}`),
  },
  approvals: {
    list:    ()            => req('GET',  '/approvals/'),
    pending: ()            => req('GET',  '/approvals/pending'),
    decide:  (id, status)  => req('POST', `/approvals/${id}/decide`, { status }),
  },
  ai: {
    chat:    (scanId, messages) => req('POST', '/ai/chat', { scan_id: scanId, messages }),
    analyze: (scanId, opts)     => req('POST', `/ai/analyze/${scanId}`, opts || {}),
    summary: scanId             => req('GET',  `/ai/scan/${scanId}/summary`),
  },
  agent: {
    capabilities: ()      => req('GET',  '/agent/capabilities'),
    modelRoute:   (q)     => req('GET',  `/agent/model-route?q=${encodeURIComponent(q || '')}`),
    command:      (data)  => req('POST', '/agent/command', data),
  },
  live: {
    status:   () => req('GET', '/live/status'),
    snapshot: () => req('GET', '/live/snapshot'),
  },
  liveData: {
    capabilities: () => req('GET', '/live-data/capabilities'),
    query: (query) => req('POST', '/live-data/query', { query }),
  },
  programs: {
    list:     (opts={}) => {
      const q = new URLSearchParams(opts).toString()
      return req('GET', '/programs/' + (q ? '?' + q : ''))
    },
    snapshot: () => req('GET', '/programs/snapshot'),
    sources:  () => req('GET', '/programs/sources'),
    check:    (max_programs=500) => req('POST', '/programs/check', { max_programs }),
    get:      id => req('GET', `/programs/${id}`),
    addTargets: (id, limit=25) => req('POST', `/programs/${id}/add-targets`, { limit }),
    opportunities: (params={}) => { const q = new URLSearchParams(params).toString(); return req('GET', `/programs/opportunities${q ? '?' + q : ''}`) },
    recommendEasy: (params={}) => { const q = new URLSearchParams(params).toString(); return req('GET', `/programs/recommend-easy${q ? '?' + q : ''}`) },
    opportunity: id => req('GET', `/programs/${id}/opportunity`),
  },
  accounts: {
    capabilities: () => req('GET', '/accounts/capabilities'),
    snapshot: () => req('GET', '/accounts/snapshot'),
    list: (opts={}) => {
      const q = new URLSearchParams(opts).toString()
      return req('GET', '/accounts/' + (q ? '?' + q : ''))
    },
    create: (data) => req('POST', '/accounts/', data),
    get: (id) => req('GET', `/accounts/${id}`),
    test: (id) => req('POST', `/accounts/${id}/test`, {}),
    sync: (id, data={}) => req('POST', `/accounts/${id}/sync`, data),
    syncAll: (data={}) => req('POST', '/accounts/sync-all', data),
    updateToken: (id, data) => req('POST', `/accounts/${id}/token`, data),
    delete: (id) => req('DELETE', `/accounts/${id}`),
  },
  connectorHealth: {
    snapshot: () => req('GET', '/connector-health/'),
    get: provider => req('GET', `/connector-health/${encodeURIComponent(provider)}`),
    reset: provider => provider
      ? req('POST', `/connector-health/${encodeURIComponent(provider)}/reset`, {})
      : req('POST', '/connector-health/reset', {}),
  },
  hunter: {
    capabilities: () => req('GET', '/hunter/capabilities'),
    run: (scanId, data={}) => req('POST', `/hunter/scans/${scanId}/run`, data),
    snapshot: scanId => req('GET', `/hunter/scans/${scanId}/snapshot`),
    graph: scanId => req('GET', `/hunter/scans/${scanId}/graph`),
    hypotheses: scanId => req('GET', `/hunter/scans/${scanId}/hypotheses`),
    plan: scanId => req('GET', `/hunter/scans/${scanId}/plan`),
    createValidation: decisionId => req('POST', '/hunter/validations', { decision_id: decisionId }),
    approveValidation: (attemptId, approved=true) => req('POST', `/hunter/validations/${attemptId}/approval`, { approved }),
    executeValidation: (attemptId, dryRun=true) => req('POST', `/hunter/validations/${attemptId}/execute`, { dry_run: dryRun }),
    generateReport: (scanId, data={}) => req('POST', `/hunter/scans/${scanId}/reports`, data),
    reports: scanId => req('GET', `/hunter/scans/${scanId}/reports`),
    memory: scanId => req('GET', `/hunter/scans/${scanId}/memory`),
    experience: scanId => req('GET', `/hunter/experience${scanId ? `?scan_id=${encodeURIComponent(scanId)}` : ''}`),
    labs: () => req('GET', '/hunter/labs'),
    createLab: (id, data={}) => req('POST', `/hunter/labs/${id}/create`, data),
  },
  quality: {
    capabilities: () => req('GET', '/quality/capabilities'),
    evaluate: (scanId, data={}) => req('POST', `/quality/scans/${scanId}/evaluate`, data),
    scan: scanId => req('GET', `/quality/scans/${scanId}`),
    evaluations: (params={}) => { const q = new URLSearchParams(params).toString(); return req('GET', `/quality/evaluations${q ? '?' + q : ''}`) },
    retry: evaluationId => req('POST', `/quality/evaluations/${evaluationId}/retry`, {}),
    performance: () => req('GET', '/quality/performance'),
  },
  tools: () => req('GET', '/tools'),
}
