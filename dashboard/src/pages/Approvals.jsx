import React, { useState, useEffect } from 'react'
import { api } from '../lib/api'

function ApprovalCard({ approval, onDecide }) {
  const [loading, setLoading] = useState(null)

  const decide = async (status) => {
    setLoading(status)
    try {
      await api.approvals.decide(approval.id, status)
      onDecide()
    } catch (e) {
      alert(e.message)
    } finally {
      setLoading(null)
    }
  }

  const isPending = approval.status === 'pending'

  return (
    <div className="card" style={{
      borderColor: isPending ? 'rgba(255,209,102,0.4)' : 'var(--border)',
      transition: 'border-color 0.2s',
    }}>
      {/* Card header */}
      <div style={{
        padding: '10px 14px',
        background: isPending ? 'rgba(255,209,102,0.05)' : 'transparent',
        borderBottom: '1px solid var(--border)',
        display: 'flex',
        alignItems: 'center',
        gap: 10,
      }}>
        <span style={{ fontSize: 16 }}>⚠️</span>
        <span style={{ flex: 1, fontWeight: 700, fontSize: 14 }}>{approval.action}</span>
        <span className={`badge ${approval.status}`}>{approval.status}</span>
      </div>

      {/* Card body */}
      <div style={{ padding: 14 }}>
        <div style={{ marginBottom: 10 }}>
          <div className="label">PHASE</div>
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--accent)' }}>
            {approval.phase}
          </div>
        </div>

        {approval.context && (
          <div style={{ marginBottom: 12 }}>
            <div className="label">AI REASONING & CONTEXT</div>
            <div style={{
              padding: '8px 10px',
              background: 'var(--bg-base)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              color: 'var(--text-dim)',
              whiteSpace: 'pre-wrap',
              lineHeight: 1.6,
              maxHeight: 180,
              overflow: 'auto',
            }}>
              {approval.context}
            </div>
          </div>
        )}

        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginBottom: 12 }}>
          REQUESTED: {new Date(approval.created_at).toLocaleString()}
          {approval.decided_at && ` · DECIDED: ${new Date(approval.decided_at).toLocaleString()}`}
        </div>

        {isPending && (
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn success"
              onClick={() => decide('approved')}
              disabled={!!loading}
              style={{ flex: 1, justifyContent: 'center' }}
            >
              {loading === 'approved' ? 'APPROVING...' : '✓ APPROVE'}
            </button>
            <button
              className="btn danger"
              onClick={() => decide('rejected')}
              disabled={!!loading}
              style={{ flex: 1, justifyContent: 'center' }}
            >
              {loading === 'rejected' ? 'REJECTING...' : '✕ REJECT'}
            </button>
          </div>
        )}

        {!isPending && (
          <div style={{
            fontFamily: 'var(--font-mono)',
            fontSize: 11,
            color: approval.status === 'approved' ? 'var(--green)' : 'var(--red)',
            padding: '6px 10px',
            background: approval.status === 'approved' ? 'var(--green-dim)' : 'var(--red-dim)',
            border: `1px solid ${approval.status === 'approved' ? 'rgba(0,255,157,0.2)' : 'rgba(255,59,92,0.2)'}`,
            borderRadius: 'var(--radius)',
          }}>
            {approval.status === 'approved' ? '✓ APPROVED — step executed by exploit agent' : '✕ REJECTED — step skipped'}
          </div>
        )}
      </div>
    </div>
  )
}

export default function Approvals() {
  const [approvals, setApprovals] = useState([])
  const [loading, setLoading] = useState(true)
  const [filter, setFilter] = useState('pending')

  const load = () => {
    setLoading(true)
    api.approvals.list()
      .then(a => setApprovals(a.sort((x, y) => new Date(y.created_at) - new Date(x.created_at))))
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    const t = setInterval(load, 4000)
    return () => clearInterval(t)
  }, [])

  const filtered = filter === 'all'
    ? approvals
    : approvals.filter(a => a.status === filter)

  const pendingCount = approvals.filter(a => a.status === 'pending').length

  return (
    <div style={{ padding: 24, height: '100%', overflow: 'auto' }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
          <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', letterSpacing: 2, fontSize: 13 }}>
            // APPROVAL GATE
          </div>
          {pendingCount > 0 && (
            <span style={{
              background: 'var(--yellow)',
              color: '#000',
              fontFamily: 'var(--font-mono)',
              fontWeight: 700,
              fontSize: 11,
              padding: '2px 8px',
              borderRadius: 2,
              animation: 'pulse 2s infinite',
            }}>
              {pendingCount} PENDING
            </span>
          )}
        </div>
        <div style={{ color: 'var(--text-muted)', fontSize: 12, fontFamily: 'var(--font-mono)' }}>
          The AI Coordinator requires human approval before executing destructive steps.
        </div>
      </div>

      {/* Filter tabs */}
      <div style={{ display: 'flex', gap: 0, borderBottom: '1px solid var(--border)', marginBottom: 16 }}>
        {['pending', 'approved', 'rejected', 'all'].map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              padding: '6px 16px',
              fontFamily: 'var(--font-mono)',
              fontSize: 11,
              letterSpacing: 1,
              textTransform: 'uppercase',
              background: 'none',
              border: 'none',
              borderBottom: filter === f ? '2px solid var(--accent)' : '2px solid transparent',
              color: filter === f ? 'var(--accent)' : 'var(--text-muted)',
              cursor: 'pointer',
            }}
          >
            {f}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="empty-state"><div style={{ color: 'var(--accent)' }}>⟳</div><div>LOADING...</div></div>
      ) : filtered.length === 0 ? (
        <div className="empty-state">
          <div style={{ fontSize: 28 }}>⊘</div>
          <div>NO {filter.toUpperCase()} APPROVALS</div>
          {filter === 'pending' && (
            <div style={{ color: 'var(--text-muted)' }}>
              Approvals appear here when the AI proposes a destructive exploit step.
            </div>
          )}
        </div>
      ) : (
        <div style={{ display: 'grid', gap: 12 }}>
          {filtered.map(a => (
            <ApprovalCard key={a.id} approval={a} onDecide={load} />
          ))}
        </div>
      )}
    </div>
  )
}
