import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'

const STATUS_ORDER = ['running', 'pending', 'done', 'failed']

export default function Scans() {
  const [scans, setScans] = useState([])
  const [targets, setTargets] = useState({})
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  const load = async () => {
    try {
      const [s, t] = await Promise.all([api.scans.list(), api.targets.list()])
      const tMap = Object.fromEntries(t.map(x => [x.id, x]))
      setScans(s.sort((a, b) =>
        STATUS_ORDER.indexOf(a.status) - STATUS_ORDER.indexOf(b.status) ||
        new Date(b.created_at) - new Date(a.created_at)
      ))
      setTargets(tMap)
    } catch (_) {}
    finally { setLoading(false) }
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [])

  const cancel = async (e, id) => {
    e.stopPropagation()
    await api.scans.cancel(id).catch(() => {})
    load()
  }

  const duration = (scan) => {
    if (!scan.started_at) return '—'
    const end = scan.finished_at ? new Date(scan.finished_at) : new Date()
    const s = Math.floor((end - new Date(scan.started_at)) / 1000)
    if (s < 60) return `${s}s`
    return `${Math.floor(s / 60)}m ${s % 60}s`
  }

  return (
    <div style={{ padding: 24, height: '100%', overflow: 'auto' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
        <div>
          <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', letterSpacing: 2, fontSize: 13 }}>
            // SCANS
          </div>
          <div style={{ color: 'var(--text-muted)', fontSize: 12, marginTop: 2 }}>
            {scans.filter(s => s.status === 'running').length} active
          </div>
        </div>
        <button className="btn" onClick={load}>⟳ REFRESH</button>
      </div>

      {loading ? (
        <div className="empty-state"><div style={{ color: 'var(--accent)' }}>⟳</div><div>LOADING...</div></div>
      ) : scans.length === 0 ? (
        <div className="empty-state">
          <div style={{ fontSize: 28 }}>⬡</div>
          <div>NO SCANS YET</div>
          <div style={{ color: 'var(--text-muted)' }}>Launch a scan from the Targets page.</div>
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 8 }}>
          {scans.map(scan => {
            const target = targets[scan.target_id]
            const isRunning = scan.status === 'running'
            return (
              <div
                key={scan.id}
                className="card"
                onClick={() => navigate(`/scans/${scan.id}`)}
                style={{
                  padding: '12px 16px',
                  cursor: 'pointer',
                  borderColor: isRunning ? 'rgba(0,212,255,0.3)' : 'var(--border)',
                  transition: 'border-color 0.15s',
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  {/* Status indicator */}
                  <div style={{
                    width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                    background: isRunning ? 'var(--accent)' :
                      scan.status === 'done' ? 'var(--green)' :
                      scan.status === 'failed' ? 'var(--red)' : 'var(--yellow)',
                    boxShadow: isRunning ? '0 0 8px var(--accent)' : 'none',
                    animation: isRunning ? 'pulse 1.5s infinite' : 'none',
                  }} />

                  {/* Target info */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 13,
                        color: 'var(--text-primary)',
                      }}>
                        {target?.domain || scan.target_id.slice(0, 8)}
                      </span>
                      <span className={`badge ${scan.status}`}>{scan.status}</span>
                      <span style={{
                        fontFamily: 'var(--font-mono)',
                        fontSize: 10,
                        color: 'var(--text-muted)',
                        textTransform: 'uppercase',
                        letterSpacing: 1,
                      }}>
                        [{scan.phase}]
                      </span>
                    </div>
                    <div style={{
                      fontFamily: 'var(--font-mono)',
                      fontSize: 10,
                      color: 'var(--text-muted)',
                      marginTop: 2,
                    }}>
                      {scan.id.slice(0, 16)}... · {duration(scan)} · {new Date(scan.created_at).toLocaleString()}
                    </div>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: 6, flexShrink: 0 }}>
                    {isRunning && (
                      <button
                        className="btn danger sm"
                        onClick={(e) => cancel(e, scan.id)}
                      >
                        CANCEL
                      </button>
                    )}
                    <div style={{
                      color: 'var(--text-muted)',
                      fontSize: 16,
                      padding: '0 4px',
                    }}>›</div>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}
