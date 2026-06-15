import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'

const SEVERITIES = ['all', 'critical', 'high', 'medium', 'low', 'info']

export default function Findings() {
  const [findings, setFindings] = useState([])
  const [loading, setLoading] = useState(true)
  const [sev, setSev] = useState('all')
  const [expanded, setExpanded] = useState(null)

  const load = () => {
    setLoading(true)
    api.findings.list(sev === 'all' ? null : sev)
      .then(setFindings)
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { load() }, [sev])

  const toggleFP = async (f) => {
    await api.findings.update(f.id, { false_positive: !f.false_positive })
    load()
  }

  const del = async (f) => {
    if (!confirm(`Delete finding: ${f.title}?`)) return
    await api.findings.delete(f.id)
    load()
  }

  const sevCounts = findings.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1
    return acc
  }, {})

  return (
    <div style={{ padding: 24, height: '100%', overflow: 'auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', letterSpacing: 2, fontSize: 13, marginBottom: 12 }}>
          // FINDINGS
        </div>

        {/* Severity summary badges */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginBottom: 14 }}>
          {['critical','high','medium','low','info'].map(s => (
            sevCounts[s] > 0 && (
              <span key={s} className={`badge ${s}`}>{sevCounts[s]} {s}</span>
            )
          ))}
        </div>

        {/* Filter tabs */}
        <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)' }}>
          {SEVERITIES.map(s => (
            <button
              key={s}
              onClick={() => setSev(s)}
              style={{
                padding: '6px 14px',
                fontFamily: 'var(--font-mono)',
                fontSize: 11,
                letterSpacing: 1,
                textTransform: 'uppercase',
                background: 'none',
                border: 'none',
                borderBottom: sev === s ? '2px solid var(--accent)' : '2px solid transparent',
                color: sev === s ? 'var(--accent)' : 'var(--text-muted)',
                cursor: 'pointer',
              }}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Findings table */}
      {loading ? (
        <div className="empty-state"><div style={{ color: 'var(--accent)' }}>⟳</div><div>LOADING...</div></div>
      ) : findings.length === 0 ? (
        <div className="empty-state">
          <div style={{ fontSize: 28 }}>⚑</div>
          <div>NO FINDINGS</div>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 6 }}>
          {findings
            .sort((a, b) => {
              const o = ['critical','high','medium','low','info']
              return o.indexOf(a.severity) - o.indexOf(b.severity)
            })
            .map(f => (
              <div key={f.id} className="card" style={{
                opacity: f.false_positive ? 0.5 : 1,
                transition: 'opacity 0.2s',
              }}>
                {/* Row header */}
                <div
                  onClick={() => setExpanded(expanded === f.id ? null : f.id)}
                  style={{
                    padding: '10px 14px',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 10,
                    cursor: 'pointer',
                  }}
                >
                  <span className={`badge ${f.severity}`}>{f.severity}</span>
                  <span style={{ flex: 1, fontWeight: 600, fontSize: 13 }}>{f.title}</span>
                  <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                    {f.cwe_id && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--purple)' }}>
                        {f.cwe_id}
                      </span>
                    )}
                    {f.cvss_score && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--yellow)' }}>
                        CVSS {f.cvss_score}
                      </span>
                    )}
                    {f.tool && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)' }}>
                        [{f.tool}]
                      </span>
                    )}
                    {f.false_positive && (
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 9, color: 'var(--text-muted)', border: '1px solid var(--border)', padding: '1px 5px', borderRadius: 2 }}>
                        FALSE POSITIVE
                      </span>
                    )}
                    <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>
                      {expanded === f.id ? '▲' : '▼'}
                    </span>
                  </div>
                </div>

                {/* Expanded detail */}
                {expanded === f.id && (
                  <div style={{
                    padding: '0 14px 14px',
                    borderTop: '1px solid var(--border)',
                    paddingTop: 12,
                  }}>
                    {f.url && (
                      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)', marginBottom: 8 }}>
                        {f.url}
                      </div>
                    )}
                    {f.description && (
                      <div style={{ fontSize: 13, color: 'var(--text-dim)', marginBottom: 10, lineHeight: 1.6 }}>
                        {f.description}
                      </div>
                    )}
                    {f.evidence && (
                      <div style={{ marginBottom: 10 }}>
                        <div className="label">EVIDENCE</div>
                        <div style={{
                          padding: '8px 10px',
                          background: 'var(--bg-base)',
                          border: '1px solid var(--border)',
                          borderRadius: 'var(--radius)',
                          fontFamily: 'var(--font-mono)',
                          fontSize: 11,
                          color: 'var(--green)',
                          whiteSpace: 'pre-wrap',
                          wordBreak: 'break-all',
                          maxHeight: 150,
                          overflow: 'auto',
                        }}>
                          {f.evidence}
                        </div>
                      </div>
                    )}
                    {f.remediation && (
                      <div style={{
                        padding: '8px 10px',
                        background: 'var(--yellow-dim)',
                        border: '1px solid rgba(255,209,102,0.2)',
                        borderRadius: 'var(--radius)',
                        fontFamily: 'var(--font-mono)',
                        fontSize: 11,
                        color: 'var(--yellow)',
                        marginBottom: 10,
                      }}>
                        ⚠ REMEDIATION: {f.remediation}
                      </div>
                    )}
                    <div style={{ display: 'flex', gap: 6 }}>
                      <button className="btn sm" onClick={() => toggleFP(f)}>
                        {f.false_positive ? 'MARK REAL' : 'MARK FP'}
                      </button>
                      <button className="btn danger sm" onClick={() => del(f)}>DELETE</button>
                    </div>
                  </div>
                )}
              </div>
            ))}
        </div>
      )}
    </div>
  )
}
