import React, { useState, useEffect, useRef } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { api } from '../lib/api'
import AttackGraph from '../components/AttackGraph'

const PHASE_ORDER = ['recon', 'vulnscan', 'exploit']
const SEV_ORDER   = { critical: 0, high: 1, medium: 2, low: 3, info: 4 }

function PhaseBar({ current, status }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 0 }}>
      {PHASE_ORDER.map((phase, i) => {
        const ci   = PHASE_ORDER.indexOf(current)
        const done = ci > i || (ci === i && status === 'done')
        const act  = phase === current && status === 'running'
        return (
          <React.Fragment key={phase}>
            <div style={{
              padding:'4px 14px', fontFamily:'var(--font-mono)', fontSize:10,
              letterSpacing:1, textTransform:'uppercase',
              background: act ? 'var(--accent-dim)' : done ? 'var(--green-dim)' : 'transparent',
              color:      act ? 'var(--accent)'     : done ? 'var(--green)'     : 'var(--text-muted)',
              border:`1px solid ${act?'var(--accent)':done?'rgba(0,255,157,0.3)':'var(--border)'}`,
              borderRadius:'var(--radius)', transition:'all 0.3s',
            }}>
              {act && <span style={{marginRight:4,animation:'blink 1s infinite'}}>▶</span>}
              {done && !act && <span style={{marginRight:4}}>✓</span>}
              {phase}
            </div>
            {i < PHASE_ORDER.length-1 && <div style={{width:20,height:1,background:done?'var(--green)':'var(--border)'}} />}
          </React.Fragment>
        )
      })}
    </div>
  )
}

export default function ScanDetail() {
  const { id }  = useParams()
  const navigate= useNavigate()
  const [scan,setScan]         = useState(null)
  const [target,setTarget]     = useState(null)
  const [events,setEvents]     = useState([])
  const [findings,setFindings] = useState([])
  const [tab,setTab]           = useState('console')
  const [filter,setFilter]     = useState('all')
  const [aiSum,setAiSum]       = useState(null)
  const [loadSum,setLoadSum]   = useState(false)
  const [split,setSplit]       = useState(true)
  const consoleRef = useRef(null)
  const autoScroll = useRef(true)

  const loadData = async () => {
    try {
      const s = await api.scans.get(id)
      setScan(s)
      const t = await api.targets.get(s.target_id)
      setTarget(t)
      const f = await api.scans.findings(id)
      setFindings(f)
    } catch(_) {}
  }

  useEffect(() => {
    loadData()
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(`${protocol}//${window.location.host}/ws/scans/${id}`)
    ws.onmessage = e => {
      try {
        const ev = JSON.parse(e.data)
        if (ev.scan_id) setEvents(prev => prev.find(x=>x.id===ev.id) ? prev : [...prev,ev])
      } catch(_) {}
    }
    ws.onopen = () => { const t = setInterval(()=>ws.readyState===1&&ws.send('ping'),25000); ws._t=t }
    ws.onclose= () => clearInterval(ws._t)
    const poll = setInterval(async()=>{
      try {
        const [s,f] = await Promise.all([api.scans.get(id),api.scans.findings(id)])
        setScan(s); setFindings(f)
      } catch(_) {}
    },4000)
    return () => { ws.close(); clearInterval(poll) }
  }, [id])

  useEffect(() => {
    if (autoScroll.current && consoleRef.current)
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight
  }, [events])

  const filtered = filter === 'all' ? events : events.filter(e=>e.level===filter)
  const modeBadge = scan?.mode === 'aggressive'
    ? { label:'AGGRESSIVE', color:'var(--red)' }
    : { label:'PASSIVE',    color:'var(--green)' }

  if (!scan) return <div className="empty-state" style={{height:'100%'}}><div style={{color:'var(--accent)'}}>⟳</div><div>LOADING...</div></div>

  return (
    <div style={{display:'flex',flexDirection:'column',height:'100%'}}>
      {/* Header */}
      <div style={{padding:'12px 20px',borderBottom:'1px solid var(--border)',background:'var(--bg-surface)',flexShrink:0}}>
        <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:8}}>
          <button onClick={()=>navigate('/scans')} style={{background:'none',border:'none',color:'var(--text-dim)',cursor:'pointer',fontSize:20}}>‹</button>
          <span style={{fontFamily:'var(--font-mono)',color:'var(--accent)',fontSize:13}}>{target?.domain||id}</span>
          <span className={`badge ${scan.status}`}>{scan.status}</span>
          <span style={{fontFamily:'var(--font-mono)',fontSize:10,padding:'1px 7px',borderRadius:2,border:`1px solid ${modeBadge.color}33`,color:modeBadge.color}}>{modeBadge.label}</span>
          {scan.status==='running' && <span className="pulse-dot" />}
          <div style={{flex:1}} />
          <button className="btn sm" onClick={()=>setSplit(s=>!s)}>{split?'FULL CONSOLE':'SPLIT VIEW'}</button>
          {scan.status==='done' && <button className="btn primary sm" onClick={async()=>{setLoadSum(true);try{const r=await api.ai.summary(id);setAiSum(r.summary);setTab('summary')}catch(e){setAiSum('Error: '+e.message)}finally{setLoadSum(false)}}} disabled={loadSum}>{loadSum?'...':'⬡ AI SUMMARY'}</button>}
        </div>
        <PhaseBar current={scan.phase} status={scan.status} />
      </div>

      {/* Stats */}
      <div style={{display:'flex',borderBottom:'1px solid var(--border)',background:'var(--bg-elevated)',flexShrink:0}}>
        {[
          {label:'EVENTS',   val:events.length,                                      color:'var(--text-primary)'},
          {label:'FINDINGS', val:findings.length,                                    color:'var(--yellow)'},
          {label:'CRITICAL', val:findings.filter(f=>f.severity==='critical').length, color:'var(--red)'},
          {label:'HIGH',     val:findings.filter(f=>f.severity==='high').length,     color:'var(--orange)'},
          {label:'CHAINS',   val:findings.filter(f=>f.title?.startsWith('[CHAIN]')).length, color:'var(--purple)'},
        ].map(({label,val,color}) => (
          <div key={label} style={{padding:'6px 18px',borderRight:'1px solid var(--border)',fontFamily:'var(--font-mono)'}}>
            <div style={{fontSize:18,fontWeight:700,color}}>{val}</div>
            <div style={{fontSize:9,color:'var(--text-muted)',letterSpacing:1}}>{label}</div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div style={{display:'flex',borderBottom:'1px solid var(--border)',background:'var(--bg-surface)',flexShrink:0}}>
        {['console','graph','findings','summary'].map(t=>(
          <button key={t} onClick={()=>setTab(t)} style={{
            padding:'8px 18px',fontFamily:'var(--font-mono)',fontSize:11,letterSpacing:1,textTransform:'uppercase',
            background:'none',border:'none',cursor:'pointer',
            borderBottom:tab===t?'2px solid var(--accent)':'2px solid transparent',
            color:tab===t?'var(--accent)':'var(--text-dim)',transition:'all 0.15s',
          }}>
            {t}
            {t==='findings'&&findings.length>0&&<span style={{marginLeft:5,background:'var(--yellow-dim)',color:'var(--yellow)',borderRadius:2,padding:'0 4px',fontSize:9}}>{findings.length}</span>}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{flex:1,overflow:'hidden',display:'flex'}}>

        {/* Console */}
        {tab==='console' && (
          <div style={{display:'flex',flex:1,overflow:'hidden'}}>
            <div style={{flex:1,display:'flex',flexDirection:'column',overflow:'hidden',borderRight:split?'1px solid var(--border)':'none'}}>
              <div style={{padding:'5px 10px',borderBottom:'1px solid var(--border)',display:'flex',gap:5,background:'var(--bg-elevated)',flexShrink:0}}>
                {['all','finding','warn','error','info'].map(f=>(
                  <button key={f} onClick={()=>setFilter(f)} style={{
                    padding:'2px 8px',fontFamily:'var(--font-mono)',fontSize:10,textTransform:'uppercase',
                    background:filter===f?'var(--accent-dim)':'transparent',
                    border:`1px solid ${filter===f?'var(--accent)':'var(--border)'}`,
                    color:filter===f?'var(--accent)':'var(--text-muted)',
                    borderRadius:'var(--radius)',cursor:'pointer',
                  }}>{f}</button>
                ))}
                <div style={{flex:1}} />
                <span style={{fontFamily:'var(--font-mono)',fontSize:10,color:'var(--text-muted)',paddingTop:2}}>{filtered.length} events</span>
              </div>
              <div ref={consoleRef}
                onScroll={e=>{const el=e.target;autoScroll.current=el.scrollHeight-el.scrollTop-el.clientHeight<50}}
                style={{flex:1,overflow:'auto',padding:10,fontFamily:'var(--font-mono)',fontSize:11,lineHeight:1.55,background:'var(--bg-base)'}}>
                {filtered.length===0
                  ? <div style={{color:'var(--text-muted)',padding:8}}>{scan.status==='pending'?'Queued...':'No events.'}</div>
                  : filtered.map((ev,i)=>(
                    <div key={ev.id||i} style={{display:'flex',gap:8,padding:'1px 0',background:ev.level==='finding'?'rgba(255,59,92,0.04)':'transparent',borderBottom:ev.level==='finding'?'1px solid rgba(255,59,92,0.08)':'none'}}>
                      <span style={{color:'var(--text-muted)',flexShrink:0,fontSize:10}}>{ev.created_at?new Date(ev.created_at).toLocaleTimeString():''}</span>
                      <span style={{flexShrink:0,fontSize:9,padding:'1px 4px',borderRadius:2,fontWeight:700,
                        color:ev.level==='finding'?'var(--red)':ev.level==='warn'?'var(--yellow)':ev.level==='error'?'var(--red)':'var(--text-muted)',
                        background:ev.level==='finding'?'var(--red-dim)':ev.level==='warn'?'var(--yellow-dim)':'transparent',
                      }}>{(ev.level||'info').toUpperCase()}</span>
                      <span style={{color:'var(--accent)',flexShrink:0,fontSize:10}}>[{ev.tool||'?'}]</span>
                      <span style={{wordBreak:'break-all',color:ev.level==='finding'?'var(--red)':ev.level==='warn'?'var(--yellow)':ev.level==='error'?'var(--red)':'var(--text-primary)'}}>{ev.message}</span>
                    </div>
                  ))
                }
                {scan.status==='running'&&<div style={{color:'var(--accent)',marginTop:4}}><span style={{animation:'blink 1s infinite'}}>█</span></div>}
              </div>
            </div>
            {split && (
              <div style={{width:'38%',minWidth:260,flexShrink:0,overflow:'hidden'}}>
                <AttackGraph events={events} findings={findings} scanStatus={scan.status} />
              </div>
            )}
          </div>
        )}

        {/* Full graph */}
        {tab==='graph' && (
          <div style={{flex:1,overflow:'hidden'}}>
            <AttackGraph events={events} findings={findings} scanStatus={scan.status} />
          </div>
        )}

        {/* Findings */}
        {tab==='findings' && (
          <div style={{flex:1,padding:14,overflow:'auto'}}>
            {findings.length===0
              ? <div className="empty-state"><div>⚑</div><div>NO FINDINGS YET</div></div>
              : <div style={{display:'grid',gap:8}}>
                  {[...findings].sort((a,b)=>(SEV_ORDER[a.severity]??5)-(SEV_ORDER[b.severity]??5)).map(f=>(
                    <div key={f.id} className="card" style={{padding:12}}>
                      <div style={{display:'flex',alignItems:'flex-start',gap:10}}>
                        <span className={`badge ${f.severity}`}>{f.severity}</span>
                        <div style={{flex:1}}>
                          <div style={{fontWeight:600,marginBottom:4,fontSize:13}}>{f.title}</div>
                          <div style={{display:'flex',gap:10,fontFamily:'var(--font-mono)',fontSize:10,color:'var(--text-muted)',flexWrap:'wrap'}}>
                            {f.tool&&<span>tool:{f.tool}</span>}
                            {f.cwe_id&&<span style={{color:'var(--purple)'}}>{f.cwe_id}</span>}
                            {f.cvss_score&&<span>CVSS:{f.cvss_score}</span>}
                          </div>
                          {f.url&&<div style={{fontFamily:'var(--font-mono)',fontSize:10,color:'var(--accent)',marginTop:4}}>{f.url}</div>}
                          {f.evidence&&<div style={{marginTop:8,padding:'6px 8px',background:'var(--bg-base)',border:'1px solid var(--border)',borderRadius:'var(--radius)',fontFamily:'var(--font-mono)',fontSize:10,color:'var(--green)',whiteSpace:'pre-wrap',maxHeight:100,overflow:'auto'}}>{f.evidence}</div>}
                          {f.remediation&&<div style={{marginTop:6,fontFamily:'var(--font-mono)',fontSize:10,color:'var(--yellow)'}}>⚠ {f.remediation}</div>}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
            }
          </div>
        )}

        {/* Summary */}
        {tab==='summary' && (
          <div style={{flex:1,padding:24,overflow:'auto'}}>
            {!aiSum
              ? <div className="empty-state"><div style={{fontSize:28}}>⬡</div><div>NO SUMMARY YET</div><button className="btn primary" onClick={async()=>{setLoadSum(true);try{const r=await api.ai.summary(id);setAiSum(r.summary)}catch(e){setAiSum('Error: '+e.message)}finally{setLoadSum(false)}}} disabled={loadSum} style={{marginTop:12}}>{loadSum?'GENERATING...':'GENERATE AI SUMMARY'}</button></div>
              : <div style={{fontFamily:'var(--font-mono)',fontSize:12,color:'var(--text-primary)',lineHeight:1.8,whiteSpace:'pre-wrap',maxWidth:800}}>{aiSum}</div>
            }
          </div>
        )}
      </div>
    </div>
  )
}
