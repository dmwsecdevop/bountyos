import React, { useState, useEffect } from 'react'

const BASE = '/api/v1'

async function req(method, path, body) {
  const r = await fetch(BASE + path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  })
  if (!r.ok) throw new Error((await r.json().catch(() => ({}))).detail || r.statusText)
  if (r.status === 204) return null
  return r.json()
}

function StatusCard({ name, icon, status, url, note, actions }) {
  return (
    <div className="card" style={{ padding: 16, marginBottom: 12 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10 }}>
        <span style={{ fontSize: 22 }}>{icon}</span>
        <div style={{ flex: 1 }}>
          <div style={{ fontWeight: 700, fontSize: 14 }}>{name}</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)' }}>{url}</div>
        </div>
        <span className={`badge ${status === true ? 'done' : status === false ? 'failed' : 'pending'}`}>
          {status === true ? 'CONNECTED' : status === false ? 'OFFLINE' : 'CHECKING...'}
        </span>
      </div>
      {note && (
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-muted)', marginBottom: 10, lineHeight: 1.5 }}>
          {note}
        </div>
      )}
      {actions && (
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {actions.map(a => (
            <button key={a.label} className={`btn sm ${a.cls || ''}`} onClick={a.fn} disabled={a.disabled}>
              {a.label}
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export default function Integrations() {
  const [caido,  setCaido]  = useState(null)
  const [burp,   setBurp]   = useState(null)
  const [zap,    setZap]    = useState(null)
  const [msf,    setMsf]    = useState(null)
  const [scanId, setScanId] = useState('')
  const [msg,    setMsg]    = useState('')
  const [zapUrl, setZapUrl] = useState('')
  const [zapAlerts, setZapAlerts] = useState([])
  const [mdExport, setMdExport]   = useState('')

  const check = async () => {
    const [c, b, z, m] = await Promise.allSettled([
      req('GET', '/integrations/caido/status'),
      req('GET', '/integrations/burp/status'),
      req('GET', '/integrations/zap/status'),
      req('GET', '/integrations/metasploit/status'),
    ])
    setCaido(c.status === 'fulfilled' ? c.value.connected : false)
    setBurp(b.status === 'fulfilled' ? b.value.connected : false)
    setZap(z.status === 'fulfilled' ? z.value.connected : false)
    setMsf(m.status === 'fulfilled' ? m.value.connected : false)
  }

  useEffect(() => { check() }, [])

  const pushCaido = async () => {
    if (!scanId) { setMsg('Enter a scan ID first'); return }
    try {
      const r = await req('POST', `/integrations/caido/push/${scanId}`)
      setMsg(`✅ ${r.message}`)
    } catch(e) { setMsg(`❌ ${e.message}`) }
  }

  const pushBurp = async () => {
    if (!scanId) { setMsg('Enter a scan ID first'); return }
    try {
      const r = await req('POST', `/integrations/burp/push/${scanId}`)
      setMsg(`✅ ${r.message}`)
    } catch(e) { setMsg(`❌ ${e.message}`) }
  }

  const fetchZapAlerts = async () => {
    try {
      const r = await req('GET', `/integrations/zap/alerts?url=${encodeURIComponent(zapUrl)}`)
      setZapAlerts(r.alerts || [])
      setMsg(`✅ ${r.count} ZAP alerts fetched`)
    } catch(e) { setMsg(`❌ ${e.message}`) }
  }

  const importZapAlerts = async () => {
    if (!scanId) { setMsg('Enter a scan ID first'); return }
    try {
      const r = await req('POST', `/integrations/zap/import-alerts/${scanId}?url=${encodeURIComponent(zapUrl)}`)
      setMsg(`✅ ${r.message}`)
    } catch(e) { setMsg(`❌ ${e.message}`) }
  }

  const exportMd = async () => {
    if (!scanId) { setMsg('Enter a scan ID first'); return }
    try {
      const r = await req('GET', `/integrations/export/${scanId}/markdown`)
      setMdExport(r.markdown)
      setMsg(`✅ Markdown exported (${r.filename})`)
    } catch(e) { setMsg(`❌ ${e.message}`) }
  }

  return (
    <div style={{ padding: 24, height: '100%', overflow: 'auto' }}>
      <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', letterSpacing: 2, fontSize: 13, marginBottom: 20 }}>
        // INTEGRATIONS
      </div>

      {/* Scan ID input */}
      <div style={{ marginBottom: 20 }}>
        <label className="label">SCAN ID (for push/import actions)</label>
        <input className="input" value={scanId} onChange={e => setScanId(e.target.value)}
          placeholder="paste scan UUID here" style={{ maxWidth: 400 }} />
      </div>

      {msg && (
        <div style={{
          padding: '8px 12px', marginBottom: 16,
          fontFamily: 'var(--font-mono)', fontSize: 12,
          background: msg.startsWith('✅') ? 'var(--green-dim)' : 'var(--red-dim)',
          border: `1px solid ${msg.startsWith('✅') ? 'rgba(0,255,157,0.3)' : 'rgba(255,59,92,0.3)'}`,
          borderRadius: 'var(--radius)', color: msg.startsWith('✅') ? 'var(--green)' : 'var(--red)',
        }}>
          {msg}
        </div>
      )}

      {/* Caido */}
      <StatusCard
        name="Caido" icon="🔵" status={caido}
        url="http://localhost:8080 (GraphQL)"
        note="Set CAIDO_API_TOKEN in environment. Open Caido → Settings → API → Create Key."
        actions={[
          { label: 'CHECK STATUS', fn: check },
          { label: 'PUSH FINDINGS → CAIDO', fn: pushCaido, cls: 'primary', disabled: !caido },
          { label: 'PULL REQUESTS', fn: async () => {
            try { const r = await req('GET','/integrations/caido/requests'); setMsg(`✅ ${r.count} requests from Caido`) }
            catch(e) { setMsg(`❌ ${e.message}`) }
          }, disabled: !caido },
        ]}
      />

      {/* Burp Suite */}
      <StatusCard
        name="Burp Suite Professional" icon="🟠" status={burp}
        url="http://localhost:1337 (REST API)"
        note="Enable REST API in Burp: Extensions → APIs → Enable. Set BURP_APIKEY env var."
        actions={[
          { label: 'PUSH TARGET → BURP', fn: pushBurp, cls: 'primary', disabled: !burp },
        ]}
      />

      {/* ZAP */}
      <StatusCard
        name="OWASP ZAP" icon="🟢" status={zap}
        url="http://localhost:8090 (REST API)"
        note="Start ZAP with API enabled: zap.sh -daemon -port 8090 -config api.key=bountyos"
        actions={[
          { label: 'FETCH ALERTS', fn: fetchZapAlerts, cls: 'primary' },
          { label: 'IMPORT TO SCAN', fn: importZapAlerts, disabled: !scanId },
          { label: 'SPIDER URL', fn: async () => {
            if (!zapUrl) { setMsg('Enter URL below'); return }
            try { const r = await req('POST',`/integrations/zap/spider?url=${encodeURIComponent(zapUrl)}`); setMsg(`✅ ZAP spider started: ${r.scan_id}`) }
            catch(e) { setMsg(`❌ ${e.message}`) }
          }},
        ]}
      />

      {/* ZAP URL input */}
      <div style={{ marginBottom: 16 }}>
        <label className="label">ZAP TARGET URL</label>
        <input className="input" value={zapUrl} onChange={e => setZapUrl(e.target.value)}
          placeholder="https://target.com" style={{ maxWidth: 400 }} />
      </div>

      {/* ZAP Alerts */}
      {zapAlerts.length > 0 && (
        <div style={{ marginBottom: 20 }}>
          <label className="label">ZAP ALERTS ({zapAlerts.length})</label>
          <div style={{ display: 'grid', gap: 6 }}>
            {zapAlerts.slice(0, 10).map((a, i) => (
              <div key={i} className="card" style={{ padding: '8px 12px', display: 'flex', gap: 10 }}>
                <span className={`badge ${a.risk?.toLowerCase() === 'high' ? 'high' : a.risk?.toLowerCase() === 'medium' ? 'medium' : 'low'}`}>{a.risk}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{a.name}</span>
                <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{a.url}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Metasploit RPC */}
      <StatusCard
        name="Metasploit RPC" icon="🔴" status={msf}
        url="127.0.0.1:55553 (msgpack RPC)"
        note={`Start: msfrpcd -P bountyos123 -S -f\nSet: MSF_RPC_PASS=bountyos123`}
        actions={[
          { label: 'LIST SESSIONS', fn: async () => {
            try { const r = await req('GET','/integrations/metasploit/sessions'); setMsg(`✅ Sessions: ${JSON.stringify(r.sessions)}`) }
            catch(e) { setMsg(`❌ ${e.message}`) }
          }, disabled: !msf },
        ]}
      />

      {/* Export */}
      <div style={{ marginTop: 24, paddingTop: 20, borderTop: '1px solid var(--border)' }}>
        <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontSize: 11, letterSpacing: 1, marginBottom: 12 }}>
          REPORT EXPORT
        </div>
        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <button className="btn primary" onClick={exportMd} disabled={!scanId}>📄 EXPORT MARKDOWN</button>
          <button className="btn" onClick={async () => {
            if (!scanId) { setMsg('Enter scan ID'); return }
            try { const r = await req('GET',`/integrations/export/${scanId}/json`); setMsg(`✅ JSON export ready (${r.findings.length} findings)`) }
            catch(e) { setMsg(`❌ ${e.message}`) }
          }} disabled={!scanId}>
            📋 EXPORT JSON
          </button>
        </div>
        {mdExport && (
          <div>
            <label className="label">MARKDOWN PREVIEW</label>
            <textarea readOnly value={mdExport}
              style={{ width: '100%', height: 300, background: 'var(--bg-base)', border: '1px solid var(--border)', borderRadius: 'var(--radius)', color: 'var(--text-dim)', fontFamily: 'var(--font-mono)', fontSize: 11, padding: 12, resize: 'vertical' }}
            />
            <button className="btn sm" style={{ marginTop: 6 }} onClick={() => navigator.clipboard.writeText(mdExport)}>COPY TO CLIPBOARD</button>
          </div>
        )}
      </div>

      {/* Setup guide */}
      <div style={{ marginTop: 24, padding: 16, background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', marginBottom: 10, letterSpacing: 1 }}>ENVIRONMENT VARIABLES</div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--text-dim)', lineHeight: 2 }}>
          {[
            ['GEMINI_API_KEY', '... (Gemini Developer API key for local mode)'],
            ['CAIDO_API_TOKEN',   'your Caido API key'],
            ['CAIDO_URL',         'http://localhost:8080 (default)'],
            ['BURP_APIKEY',       'your Burp Suite REST API key'],
            ['BURP_URL',          'http://localhost:1337 (default)'],
            ['ZAP_APIKEY',        'bountyos (default)'],
            ['ZAP_URL',           'http://localhost:8090 (default)'],
            ['MSF_RPC_PASS',      'bountyos123 (default)'],
            ['MSF_RPC_HOST',      '127.0.0.1 (default)'],
            ['DATABASE_URL',      'sqlite:///./bountyos.db (default)'],
          ].map(([k, v]) => (
            <div key={k}>
              <span style={{ color: 'var(--yellow)' }}>{k}</span>
              <span style={{ color: 'var(--text-muted)' }}> = </span>
              <span style={{ color: 'var(--text-dim)' }}>{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}
