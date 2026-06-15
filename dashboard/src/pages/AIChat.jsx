import React, { useState, useEffect, useRef } from 'react'
import { api } from '../lib/api'

export default function AIChat() {
  const [scans, setScans] = useState([])
  const [selectedScan, setSelectedScan] = useState('')
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [listening, setListening] = useState(false)
  const bottomRef = useRef(null)

  useEffect(() => {
    api.scans.list().then(setScans).catch(() => {})
  }, [])

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  const send = async () => {
    const text = input.trim()
    if (!text || loading) return

    const userMsg = { role: 'user', content: text }
    setMessages(m => [...m, userMsg])
    setInput('')
    setLoading(true)

    try {
      const commandLike = /\b(run|start|cancel|show findings|show scans|show targets|passive|aggressive|bug brain|mindset|analyze|check programs|program radar|add program targets)\b/i.test(text)
      if (commandLike) {
        const res = await api.agent.command({
          transcript: text,
          selected_scan_id: selectedScan || null,
          approve: /\bapprove\b/i.test(text),
          source: 'ai_chat',
        })
        const out = [
          `Architect Agent: ${res.act?.message || res.act?.action || 'command handled'}`,
          '',
          `Observe: ${res.observe?.target?.domain || 'no target'} / ${res.observe?.scan?.id?.slice(0,8) || 'no scan'}`,
          `Reason: ${res.reason?.action} (${Math.round((res.reason?.confidence || 0) * 100)}%)`,
          `Model: ${res.think?.model_route?.expert} → ${res.think?.model_route?.model}`,
          res.act?.requires_approval ? 'Approval needed: send again with "approve" in the message or use the LIVE page checkbox.' : '',
        ].filter(Boolean).join('\n')
        setMessages(m => [...m, { role: 'assistant', content: out }])
      } else {
        const history = [...messages, userMsg].map(m => ({
          role: m.role,
          content: m.content,
        }))
        const res = await api.ai.chat(selectedScan || null, history)
        const route = res.model_route ? `\n\n[model route: ${res.model_route.expert} / ${res.model_route.model}]` : ''
        setMessages(m => [...m, { role: 'assistant', content: res.response + route }])
      }
    } catch (e) {
      setMessages(m => [...m, {
        role: 'assistant',
        content: `Error: ${e.message}`,
        error: true,
      }])
    } finally {
      setLoading(false)
    }
  }

  const startVoice = () => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition
    if (!SpeechRecognition) {
      setMessages(m => [...m, { role: 'assistant', content: 'Voice input is not supported in this browser. Use Chrome/Edge or type the command.', error: true }])
      return
    }
    const rec = new SpeechRecognition()
    rec.lang = 'en-US'
    rec.interimResults = false
    rec.maxAlternatives = 1
    rec.onstart = () => setListening(true)
    rec.onend = () => setListening(false)
    rec.onerror = (e) => {
      setListening(false)
      setMessages(m => [...m, { role: 'assistant', content: `Voice error: ${e.error || 'unknown error'}`, error: true }])
    }
    rec.onresult = (e) => {
      const text = e.results?.[0]?.[0]?.transcript || ''
      setInput(text)
    }
    rec.start()
  }

  const SUGGESTIONS = [
    'what is today us dollar rate',
    'latest CVEs for nginx',
    'bitcoin price in usd',
    'check programs',
    'run passive recon',
    'show findings',
    'run AI analysis',
    'What attack surface remains unexplored?',
  ]

  const scanLabel = (s) => {
    return `${s.id.slice(0, 8)} — ${s.status} [${s.phase}]`
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%' }}>
      {/* Header */}
      <div style={{
        padding: '14px 20px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-surface)',
        flexShrink: 0,
      }}>
        <div style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent)', letterSpacing: 2, fontSize: 13, marginBottom: 10 }}>
          // AI CHAT — BountyOS Intelligence
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <label className="label" style={{ margin: 0, whiteSpace: 'nowrap' }}>SCAN CONTEXT:</label>
          <select
            value={selectedScan}
            onChange={e => setSelectedScan(e.target.value)}
            style={{
              background: 'var(--bg-input)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 12,
              padding: '5px 8px',
              flex: 1,
              maxWidth: 400,
              outline: 'none',
            }}
          >
            <option value="">No context (general Q&A)</option>
            {scans.map(s => (
              <option key={s.id} value={s.id}>{scanLabel(s)}</option>
            ))}
          </select>
          {selectedScan && (
            <span style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 10,
              color: 'var(--green)',
              padding: '2px 8px',
              border: '1px solid rgba(0,255,157,0.3)',
              borderRadius: 2,
            }}>
              CONTEXT INJECTED
            </span>
          )}
        </div>
      </div>

      {/* Messages */}
      <div style={{ flex: 1, overflow: 'auto', padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
        {messages.length === 0 ? (
          <div style={{ margin: 'auto', textAlign: 'center', maxWidth: 480 }}>
            <div style={{
              fontFamily: 'var(--font-mono)',
              fontSize: 13,
              color: 'var(--accent)',
              marginBottom: 8,
              letterSpacing: 1,
            }}>
              BOUNTYOS AI READY
            </div>
            <div style={{ color: 'var(--text-muted)', fontSize: 12, marginBottom: 24 }}>
              Ask questions or run commands like “run passive recon”, “show findings”, or “run AI analysis”.
              {selectedScan ? ' Scan context has been injected.' : ' Select a scan above for context-aware answers.'}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {SUGGESTIONS.map(s => (
                <button
                  key={s}
                  onClick={() => setInput(s)}
                  style={{
                    padding: '8px 14px',
                    fontFamily: 'var(--font-mono)',
                    fontSize: 11,
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: 'var(--radius)',
                    color: 'var(--text-dim)',
                    cursor: 'pointer',
                    textAlign: 'left',
                    transition: 'all 0.15s',
                  }}
                  onMouseEnter={e => {
                    e.target.style.borderColor = 'var(--accent)'
                    e.target.style.color = 'var(--accent)'
                  }}
                  onMouseLeave={e => {
                    e.target.style.borderColor = 'var(--border)'
                    e.target.style.color = 'var(--text-dim)'
                  }}
                >
                  › {s}
                </button>
              ))}
            </div>
          </div>
        ) : (
          messages.map((m, i) => (
            <div
              key={i}
              style={{
                display: 'flex',
                flexDirection: m.role === 'user' ? 'row-reverse' : 'row',
                gap: 10,
                alignItems: 'flex-start',
              }}
            >
              {/* Avatar */}
              <div style={{
                width: 28,
                height: 28,
                borderRadius: 'var(--radius)',
                background: m.role === 'user' ? 'var(--accent-dim)' : 'var(--bg-elevated)',
                border: `1px solid ${m.role === 'user' ? 'var(--accent)' : 'var(--border)'}`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontFamily: 'var(--font-mono)',
                fontSize: 10,
                color: m.role === 'user' ? 'var(--accent)' : 'var(--text-dim)',
                flexShrink: 0,
              }}>
                {m.role === 'user' ? 'YOU' : 'AI'}
              </div>

              {/* Bubble */}
              <div style={{
                maxWidth: '75%',
                padding: '10px 14px',
                background: m.role === 'user' ? 'var(--accent-dim)' : 'var(--bg-card)',
                border: `1px solid ${m.role === 'user' ? 'rgba(0,212,255,0.3)' : m.error ? 'rgba(255,59,92,0.3)' : 'var(--border)'}`,
                borderRadius: 'var(--radius)',
                fontFamily: m.role === 'assistant' ? 'var(--font-mono)' : 'var(--font-ui)',
                fontSize: 13,
                color: m.error ? 'var(--red)' : 'var(--text-primary)',
                lineHeight: 1.6,
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}>
                {m.content}
              </div>
            </div>
          ))
        )}

        {loading && (
          <div style={{ display: 'flex', gap: 10, alignItems: 'flex-start' }}>
            <div style={{
              width: 28, height: 28, borderRadius: 'var(--radius)',
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-dim)',
            }}>AI</div>
            <div style={{
              padding: '10px 14px',
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              fontFamily: 'var(--font-mono)',
              fontSize: 13,
              color: 'var(--accent)',
            }}>
              <span style={{ animation: 'blink 1s infinite' }}>▊</span>
            </div>
          </div>
        )}

        <div ref={bottomRef} />
      </div>

      {/* Input */}
      <div style={{
        padding: '12px 20px',
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-surface)',
        flexShrink: 0,
      }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <textarea
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault()
                send()
              }
            }}
            placeholder="Ask about findings, exploits, remediation... (Enter to send, Shift+Enter for newline)"
            rows={2}
            style={{
              flex: 1,
              background: 'var(--bg-input)',
              border: '1px solid var(--border)',
              borderRadius: 'var(--radius)',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-mono)',
              fontSize: 13,
              padding: '8px 12px',
              outline: 'none',
              resize: 'none',
              lineHeight: 1.5,
            }}
            onFocus={e => e.target.style.borderColor = 'var(--accent)'}
            onBlur={e => e.target.style.borderColor = 'var(--border)'}
          />
          <button
            className="btn"
            onClick={startVoice}
            disabled={listening || loading}
            style={{
              alignSelf: 'flex-end',
              height: 38,
              borderColor: listening ? 'var(--green)' : 'var(--border)',
              color: listening ? 'var(--green)' : 'var(--text-dim)',
            }}
          >
            {listening ? 'LISTENING...' : '🎙 TALK'}
          </button>
          <button
            className="btn primary"
            onClick={send}
            disabled={loading || !input.trim()}
            style={{
              alignSelf: 'flex-end',
              height: 38,
            }}
          >
            SEND
          </button>
        </div>
        <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--text-muted)', marginTop: 5 }}>
          MoE routing enabled · live-data tools for USD/CVE/crypto · main model only for heavy bug reasoning
        </div>
      </div>
    </div>
  )
}
