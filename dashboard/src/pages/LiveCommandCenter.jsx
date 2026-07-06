import React, { useEffect, useMemo, useRef, useState } from 'react'
import { api } from '../lib/api'
import CaidoProxyPanel from '../components/CaidoProxyPanel'

const card = {
  background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:14,
}
const mono = { fontFamily:'var(--font-mono)' }

function Pill({ children, color='var(--accent)' }) {
  return <span style={{...mono, fontSize:10, color, border:`1px solid ${color}55`, borderRadius:2, padding:'2px 7px', background:`${color}12`}}>{children}</span>
}

function JsonLine({ label, value }) {
  return <div style={{display:'flex', gap:8, alignItems:'center', fontSize:11, color:'var(--text-dim)', ...mono}}>
    <span style={{color:'var(--text-muted)', minWidth:90}}>{label}</span>
    <span style={{color:'var(--text-primary)', overflow:'hidden', textOverflow:'ellipsis'}}>{value || '—'}</span>
  </div>
}

export default function LiveCommandCenter() {
  const [snapshot, setSnapshot] = useState(null)
  const [events, setEvents] = useState([])
  const [connected, setConnected] = useState(false)
  const [targets, setTargets] = useState([])
  const [scans, setScans] = useState([])
  const [selectedTarget, setSelectedTarget] = useState('')
  const [selectedScan, setSelectedScan] = useState('')
  const [input, setInput] = useState('run passive recon')
  const [approve, setApprove] = useState(false)
  const [agentResult, setAgentResult] = useState(null)
  const [busy, setBusy] = useState(false)
  const [listening, setListening] = useState(false)
  const bottomRef = useRef(null)

  const refresh = async () => {
    const [snap, t, s] = await Promise.all([
      api.live.snapshot().catch(()=>null),
      api.targets.list().catch(()=>[]),
      api.scans.list().catch(()=>[]),
    ])
    if (snap) {
      setSnapshot(snap)
      setEvents([...(snap.live_events || []), ...(snap.recent_scan_events || []).map(e => ({ type:'scan.db_event', payload:e, created_at:e.created_at }))].slice(-120))
    }
    setTargets(t)
    setScans(s)
    if (!selectedTarget && t[0]) setSelectedTarget(t[0].id)
    if (!selectedScan && s[0]) setSelectedScan(s[0].id)
  }

  useEffect(() => { refresh(); const timer = setInterval(refresh, 7000); return () => clearInterval(timer) }, [])

  useEffect(() => {
    const proto = location.protocol === 'https:' ? 'wss:' : 'ws:'
    const ws = new WebSocket(`${proto}//${location.host}/ws/live`)
    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onerror = () => setConnected(false)
    ws.onmessage = (msg) => {
      if (msg.data === 'pong') return
      try {
        const ev = JSON.parse(msg.data)
        setEvents(prev => [...prev, ev].slice(-160))
      } catch {}
    }
    const ping = setInterval(() => { if (ws.readyState === 1) ws.send('ping') }, 20000)
    return () => { clearInterval(ping); ws.close() }
  }, [])

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:'smooth' }) }, [events, agentResult])

  const runCommand = async () => {
    const text = input.trim()
    if (!text || busy) return
    setBusy(true)
    try {
      const res = await api.agent.command({
        transcript: text,
        selected_target_id: selectedTarget || null,
        selected_scan_id: selectedScan || null,
        approve,
        source: 'live_dashboard',
      })
      setAgentResult(res)
      setApprove(false)
      await refresh()
    } catch (e) {
      setAgentResult({ error: e.message })
    } finally {
      setBusy(false)
    }
  }

  const startVoice = () => {
    const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition
    if (!SpeechRecognition) {
      setAgentResult({ error: 'Voice input is not supported in this browser. Use Chrome/Edge or type the command.' })
      return
    }
    const rec = new SpeechRecognition()
    rec.lang = 'en-US'
    rec.interimResults = false
    rec.maxAlternatives = 1
    rec.onstart = () => setListening(true)
    rec.onend = () => setListening(false)
    rec.onerror = (e) => { setListening(false); setAgentResult({ error: `Voice error: ${e.error || 'unknown error'}` }) }
    rec.onresult = (e) => {
      const text = e.results?.[0]?.[0]?.transcript || ''
      setInput(text)
    }
    rec.start()
  }

  const agent = snapshot?.agent || {}
  const recentFindings = snapshot?.recent_findings || []
  const pendingApprovals = snapshot?.pending_approvals || []
  const activeScans = snapshot?.active_scans || []
  const recentPrograms = snapshot?.recent_programs || []
  const modelRoute = agentResult?.think?.model_route
  const needsApproval = agentResult?.act?.requires_approval

  const eventRows = useMemo(() => [...events].slice(-80), [events])

  return <div style={{padding:20, display:'flex', flexDirection:'column', gap:14}}>
    <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', gap:12}}>
      <div>
        <div style={{...mono, color:'var(--accent)', letterSpacing:2, fontSize:14}}>// LIVE COMMAND CENTER</div>
        <div style={{fontSize:12, color:'var(--text-muted)', marginTop:4}}>Realtime dashboard + Architect Agent: Observe → Reason → Think → Act</div>
      </div>
      <div style={{display:'flex', gap:8, alignItems:'center'}}>
        <Pill color={connected ? 'var(--green)' : 'var(--red)'}>{connected ? 'WS LIVE' : 'WS OFFLINE'}</Pill>
        <Pill>{agent.status || 'idle'}</Pill>
        <Pill color='var(--yellow)'>{agent.model_expert || 'local_recon'}</Pill>
      </div>
    </div>

    <div style={{display:'grid', gridTemplateColumns:'1.1fr .9fr', gap:14}}>
      <div style={card}>
        <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>ARCHITECT CHAT TOOL RUNNER</div>
        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:8, marginBottom:8}}>
          <select value={selectedTarget} onChange={e=>setSelectedTarget(e.target.value)} style={selectStyle}>
            <option value=''>Select target</option>
            {targets.map(t => <option key={t.id} value={t.id}>{t.name || t.domain} — {t.domain}</option>)}
          </select>
          <select value={selectedScan} onChange={e=>setSelectedScan(e.target.value)} style={selectStyle}>
            <option value=''>Select scan</option>
            {scans.map(s => <option key={s.id} value={s.id}>{s.id.slice(0,8)} — {s.status} / {s.phase}</option>)}
          </select>
        </div>
        <textarea value={input} onChange={e=>setInput(e.target.value)} rows={3} placeholder='Tell the agent what to do: today USD rate, latest CVEs, check programs, run passive recon, show findings, run AI analysis, cancel scan...' style={textareaStyle}/>
        <div style={{display:'flex', gap:8, alignItems:'center', marginTop:10}}>
          <button onClick={startVoice} disabled={listening || busy} className='btn' style={{color:listening?'var(--green)':'var(--text-dim)', borderColor:listening?'var(--green)':'var(--border)'}}>{listening ? 'LISTENING...' : '🎙 TALK'}</button>
          <button onClick={runCommand} disabled={busy} className='btn-primary' style={{opacity:busy?.6:1}}>{busy ? 'RUNNING...' : 'RUN COMMAND'}</button>
          <label style={{display:'flex', gap:6, alignItems:'center', color:'var(--text-dim)', fontSize:12, ...mono}}>
            <input type='checkbox' checked={approve} onChange={e=>setApprove(e.target.checked)} /> approve active action
          </label>
          {needsApproval && <Pill color='var(--yellow)'>APPROVAL NEEDED</Pill>}
        </div>

        {agentResult && <div style={{marginTop:12, display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8}}>
          <Stage title='OBSERVE' data={agentResult.observe} />
          <Stage title='REASON' data={agentResult.reason} />
          <Stage title='THINK' data={modelRoute || agentResult.think} />
          <Stage title='ACT' data={agentResult.act || agentResult.error} />
        </div>}
      </div>

      <div style={card}>
        <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>MIXTURE OF MODELS / EXPERTS</div>
        <JsonLine label='Local' value='local_recon_expert: recon, status, commands' />
        <JsonLine label='Light' value='light_triage_expert: simple Q&A' />
        <JsonLine label='Live' value='live_data_expert: USD/CVE/crypto/IP via tools' />
        <JsonLine label='Main' value='bug_reasoning_expert: after scans/findings' />
        <JsonLine label='Active' value='exploit_validation_expert: approved validation' />
        <div style={{height:1, background:'var(--border)', margin:'12px 0'}} />
        <JsonLine label='Selected' value={modelRoute?.expert || agent.model_expert} />
        <JsonLine label='Model' value={modelRoute?.model || 'heuristic-local'} />
        <JsonLine label='Workload' value={modelRoute?.workload || 'idle'} />
        <JsonLine label='Why' value={modelRoute?.reason || 'Waiting for command'} />
      </div>
    </div>

    <div style={{display:'grid', gridTemplateColumns:'repeat(5,1fr)', gap:14}}>
      <Panel title='ACTIVE SCANS' items={activeScans} empty='No active scans' render={s => <><b>{s.id.slice(0,8)}</b> {s.status} / {s.phase}</>} />
      <Panel title='LIVE FINDINGS' items={recentFindings.slice(0,8)} empty='No findings yet' render={f => <><b>{String(f.severity).toUpperCase()}</b> {f.title}</>} />
      <Panel title='PENDING APPROVALS' items={pendingApprovals.slice(0,8)} empty='No approvals pending' render={a => <><b>{a.phase}</b> {a.action}</>} />
      <Panel title='PROGRAM RADAR' items={recentPrograms.slice(0,8)} empty='No programs checked yet' render={p => <><b>{p.platform}</b> {p.name} · score {p.value_score}</>} />
      <div style={card}><CaidoProxyPanel /></div>
    </div>

    <div style={{...card, minHeight:260}}>
      <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>REALTIME EVENT FEED</div>
      <div style={{display:'flex', flexDirection:'column', gap:6, maxHeight:330, overflow:'auto'}}>
        {eventRows.map((ev, i) => <div key={i} style={{display:'grid', gridTemplateColumns:'135px 145px 1fr', gap:10, fontSize:11, ...mono, color:'var(--text-dim)', borderBottom:'1px solid var(--border)', paddingBottom:5}}>
          <span style={{color:'var(--text-muted)'}}>{(ev.created_at || '').replace('T',' ').slice(0,19)}</span>
          <span style={{color:'var(--accent)'}}>{ev.type || ev.level || 'event'}</span>
          <span style={{color:'var(--text-primary)'}}>{ev.payload?.message || ev.payload?.action || ev.message || JSON.stringify(ev.payload || ev).slice(0,220)}</span>
        </div>)}
        <div ref={bottomRef} />
      </div>
    </div>
  </div>
}

function Stage({ title, data }) {
  return <div style={{background:'var(--bg-input)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:10, minHeight:110}}>
    <div style={{...mono, color:'var(--accent)', fontSize:10, marginBottom:7}}>{title}</div>
    <pre style={{margin:0, whiteSpace:'pre-wrap', wordBreak:'break-word', color:'var(--text-dim)', fontSize:10, lineHeight:1.45, maxHeight:150, overflow:'auto'}}>{typeof data === 'string' ? data : JSON.stringify(data || {}, null, 2)}</pre>
  </div>
}

function Panel({ title, items, empty, render }) {
  return <div style={card}>
    <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>{title}</div>
    <div style={{display:'flex', flexDirection:'column', gap:7}}>
      {items?.length ? items.map((item, i) => <div key={item.id || i} style={{fontSize:12, color:'var(--text-dim)', border:'1px solid var(--border)', background:'var(--bg-input)', borderRadius:'var(--radius)', padding:8}}>{render(item)}</div>) : <div style={{fontSize:12, color:'var(--text-muted)'}}>{empty}</div>}
    </div>
  </div>
}

const selectStyle = {
  background:'var(--bg-input)', border:'1px solid var(--border)', borderRadius:'var(--radius)', color:'var(--text-primary)', fontFamily:'var(--font-mono)', fontSize:11, padding:'7px 9px', outline:'none', minWidth:0,
}
const textareaStyle = {
  width:'100%', boxSizing:'border-box', background:'var(--bg-input)', border:'1px solid var(--border)', borderRadius:'var(--radius)', color:'var(--text-primary)', fontFamily:'var(--font-mono)', fontSize:13, padding:'10px 12px', outline:'none', resize:'vertical',
}
