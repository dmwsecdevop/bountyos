import React, { useState, useEffect } from 'react'

const BASE = '/api/v1'
const req = async (method, path, body) => {
  const r = await fetch(BASE + path, { method, headers: {'Content-Type':'application/json'}, body: body ? JSON.stringify(body) : undefined })
  if (!r.ok) throw new Error((await r.json().catch(()=>({}))).detail || r.statusText)
  return r.json()
}

const PHASES = ['recon', 'vulnscan', 'exploit']
const TECHS  = ['wordpress','apache_tomcat','spring_boot','nodejs','php','graphql','aws_s3','jwt']

export default function HackerMindset() {
  const [scans, setScans]         = useState([])
  const [selectedScan, setScan]   = useState('')
  const [questions, setQuestions] = useState({})
  const [playbook, setPlaybook]   = useState('')
  const [selTech, setSelTech]     = useState('wordpress')
  const [analysis, setAnalysis]   = useState(null)
  const [loading, setLoading]     = useState(false)
  const [techs, setTechs]         = useState([])
  const [activeTab, setActiveTab] = useState('questions')

  useEffect(() => {
    fetch('/api/v1/scans/').then(r=>r.json()).then(setScans).catch(()=>{})
    // Load all phase questions on mount
    Promise.all(PHASES.map(p =>
      req('GET', `/ai/mindset/questions/${p}`).then(r => ({ [p]: r.questions }))
    )).then(results => setQuestions(Object.assign({}, ...results))).catch(()=>{})
  }, [])

  useEffect(() => {
    req('GET', `/ai/mindset/playbook/${selTech}`)
      .then(r => setPlaybook(r.playbook))
      .catch(() => setPlaybook(''))
  }, [selTech])

  useEffect(() => {
    if (!selectedScan) return
    req('GET', `/ai/mindset/technologies/${selectedScan}`)
      .then(r => setTechs(r.detected || []))
      .catch(() => {})
  }, [selectedScan])

  const runAnalysis = async () => {
    if (!selectedScan) return
    setLoading(true)
    try {
      const r = await req('POST', `/ai/mindset/analyze/${selectedScan}`)
      setAnalysis(r)
    } catch(e) {
      setAnalysis({ analysis: 'Error: ' + e.message })
    } finally { setLoading(false) }
  }

  const sevColor = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--green)', info: 'var(--text-dim)' }

  return (
    <div style={{ padding: 24, height: '100%', overflow: 'auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', letterSpacing: 2, fontSize: 13, marginBottom: 4 }}>
          // HACKER MINDSET ENGINE
        </div>
        <div style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
          How expert hackers think — injected into every AI agent
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 20 }}>
        {['questions', 'playbooks', 'analysis', 'philosophy'].map(t => (
          <button key={t} onClick={() => setActiveTab(t)} style={{
            padding: '7px 16px', fontFamily: 'var(--font-mono)', fontSize: 11, letterSpacing: 1,
            textTransform: 'uppercase', background: 'none', border: 'none', cursor: 'pointer',
            borderBottom: activeTab === t ? '2px solid var(--accent)' : '2px solid transparent',
            color: activeTab === t ? 'var(--accent)' : 'var(--text-dim)',
          }}>{t}</button>
        ))}
      </div>

      {/* Questions tab */}
      {activeTab === 'questions' && (
        <div>
          <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11, marginBottom: 16, lineHeight: 1.6 }}>
            These are the questions the AI asks itself at every step of the scan — the same questions an expert hacker asks.
          </div>
          {PHASES.map(phase => (
            <div key={phase} style={{ marginBottom: 20 }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', letterSpacing: 1, textTransform: 'uppercase', marginBottom: 10, padding: '4px 0', borderBottom: '1px solid var(--border)' }}>
                {phase} phase questions
              </div>
              <div style={{ display: 'grid', gap: 6 }}>
                {(questions[phase] || []).map((q, i) => (
                  <div key={i} style={{ display: 'flex', gap: 10, padding: '6px 10px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                    <span style={{ color: 'var(--accent)', fontFamily: 'var(--font-mono)', fontSize: 12, flexShrink: 0 }}>?</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.5 }}>{q}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Playbooks tab */}
      {activeTab === 'playbooks' && (
        <div>
          <div style={{ marginBottom: 16 }}>
            <label className="label">TECHNOLOGY</label>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {TECHS.map(t => (
                <button key={t} onClick={() => setSelTech(t)} style={{
                  padding: '4px 12px', fontFamily: 'var(--font-mono)', fontSize: 11, cursor: 'pointer',
                  borderRadius: 'var(--radius)',
                  border: `1px solid ${selTech === t ? 'var(--accent)' : 'var(--border)'}`,
                  background: selTech === t ? 'var(--accent-dim)' : 'transparent',
                  color: selTech === t ? 'var(--accent)' : 'var(--text-dim)',
                }}>
                  {t.replace(/_/g, ' ')}
                </button>
              ))}
            </div>
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', letterSpacing: 1, marginBottom: 10, textTransform: 'uppercase' }}>
            {selTech.replace(/_/g, ' ')} Attack Tree
          </div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)', lineHeight: 2, whiteSpace: 'pre-wrap', padding: '14px 16px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
            {playbook || 'Loading...'}
          </div>
        </div>
      )}

      {/* AI Analysis tab */}
      {activeTab === 'analysis' && (
        <div>
          <div style={{ marginBottom: 16 }}>
            <label className="label">SELECT SCAN</label>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
              <select value={selectedScan} onChange={e => setScan(e.target.value)} style={{
                background: 'var(--bg-input)', border: '1px solid var(--border)', borderRadius: 'var(--radius)',
                color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', fontSize: 12,
                padding: '6px 10px', flex: 1, maxWidth: 400, outline: 'none',
              }}>
                <option value="">Select a scan...</option>
                {scans.map(s => <option key={s.id} value={s.id}>{s.id.slice(0,8)} — {s.status} [{s.mode || 'passive'}]</option>)}
              </select>
              <button className="btn primary" onClick={runAnalysis} disabled={!selectedScan || loading}>
                {loading ? 'ANALYZING...' : '🧠 RUN HACKER ANALYSIS'}
              </button>
            </div>
          </div>

          {techs.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <label className="label">DETECTED TECHNOLOGIES</label>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {techs.map(t => (
                  <span key={t} style={{ padding: '3px 10px', fontFamily: 'var(--font-mono)', fontSize: 11, background: 'var(--accent-dim)', border: '1px solid var(--accent)', borderRadius: 2, color: 'var(--accent)' }}>
                    {t.replace(/_/g, ' ')}
                  </span>
                ))}
              </div>
            </div>
          )}

          {analysis && (
            <div>
              <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', fontSize: 11, letterSpacing: 1, marginBottom: 10, textTransform: 'uppercase' }}>
                AI HACKER ANALYSIS
              </div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.8, whiteSpace: 'pre-wrap', padding: '16px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
                {analysis.analysis}
              </div>
            </div>
          )}

          {!analysis && !loading && (
            <div className="empty-state">
              <div style={{ fontSize: 28 }}>🧠</div>
              <div>SELECT A SCAN AND RUN ANALYSIS</div>
              <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                The AI will generate expert attack hypotheses based on what was found
              </div>
            </div>
          )}
        </div>
      )}

      {/* Philosophy tab */}
      {activeTab === 'philosophy' && (
        <div>
          <div style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontSize: 11, marginBottom: 16 }}>
            The complete expert hacker mindset injected into every AI agent.
          </div>
          {[
            { title: 'RULE 1: INFORMATION ASYMMETRY', body: 'Every byte of information asymmetry you have over the developer is an advantage. Before touching anything, extract maximum intelligence. Error messages, response times, redirect chains, comment fields, HTTP headers, SSL certificates, DNS records — everything is a clue.' },
            { title: 'RULE 2: THINK BACKWARD FROM IMPACT', body: 'Never ask "what vulnerability can I find?" Ask: "What is the worst thing that could happen to this application?" "What data is most valuable? Where does it live?" Then work backward: what vulnerability path leads there?' },
            { title: 'RULE 3: DEVELOPERS MAKE PREDICTABLE MISTAKES', body: 'Developers think about the happy path. They forget what happens with negative numbers, very large numbers, Unicode. They forget what happens when you send the request twice (TOCTOU). They forget what happens when you skip a step in a multi-step flow. They forget whether the frontend validation is also enforced on the backend.' },
            { title: 'RULE 4: TRUST RELATIONSHIPS ARE ATTACK SURFACE', body: 'Every trust boundary is an opportunity: OAuth tokens trusted across subdomains, JWTs with weak secrets or algorithm confusion, CORS that trusts too many origins, API keys with excessive scope, subdomain trust chains, third-party integrations with broad permissions.' },
            { title: 'RULE 5: CHAIN EVERYTHING — IMPACT COMPOUNDS', body: 'A low finding + another low finding can = critical. SSRF (medium) + metadata endpoint = AWS key theft (critical). XSS (low) + admin cookie (no HttpOnly) = admin account takeover (critical). Subdomain takeover (medium) + OAuth redirect = account takeover (critical).' },
            { title: 'RULE 6: READ THE APPLICATION, NOT JUST RESPONSES', body: 'Study what the application does before you attack it. What is the authentication model? What are the user roles? What external services does it integrate with? What data does it store and where? What happens at each state transition?' },
            { title: 'RULE 7: TIMING AND BEHAVIOR ARE INFORMATION', body: 'A request that takes 3s longer when user exists = user enumeration. Different error messages for wrong user vs wrong password = user enumeration. A password reset that works differently on mobile = logic flaw. Rate limiting that resets after account lock = bypass opportunity.' },
            { title: 'RULE 8: NEVER GIVE UP ON ONE TECHNIQUE', body: 'WAF blocked your payload? Try: URL encoding, double encoding, unicode normalization, HTTP parameter pollution, alternate syntax (MySQL: /*!UNION*/, SQL Server: UNI%00ON), chunked transfer encoding, case variations, whitespace substitution, null bytes. A WAF block is not "not vulnerable" — it is "harder to exploit."' },
          ].map(({ title, body }) => (
            <div key={title} style={{ marginBottom: 12, padding: 14, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 'var(--radius)' }}>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', fontWeight: 700, marginBottom: 6, letterSpacing: 1 }}>{title}</div>
              <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--text-dim)', lineHeight: 1.7 }}>{body}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
