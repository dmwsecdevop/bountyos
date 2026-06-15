import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { api } from '../lib/api'

function TargetModal({ target, onClose, onSave }) {
  const [form, setForm] = useState(target || { name:'', domain:'', scope:'', out_of_scope:'', notes:'' })
  const [loading, setLoading] = useState(false)
  const [err, setErr] = useState(null)
  const set = k => e => setForm(f => ({...f, [k]: e.target.value}))

  const submit = async () => {
    if (!form.name || !form.domain || !form.scope) { setErr('Name, domain and scope required'); return }
    setLoading(true); setErr(null)
    try { target ? await api.targets.update(target.id, form) : await api.targets.create(form); onSave() }
    catch(e) { setErr(e.message) } finally { setLoading(false) }
  }

  return (
    <div className="modal-overlay" onClick={e => e.target===e.currentTarget && onClose()}>
      <div className="modal">
        <div className="section-title" style={{marginBottom:16}}>{target ? '// EDIT TARGET' : '// NEW TARGET'}</div>
        {[{key:'name',label:'PROGRAM NAME',ph:'HackerOne — AcmeCorp'},{key:'domain',label:'ROOT DOMAIN',ph:'acmecorp.com'},{key:'scope',label:'IN-SCOPE',ph:'*.acmecorp.com'},{key:'out_of_scope',label:'OUT-OF-SCOPE',ph:'blog.acmecorp.com'},{key:'notes',label:'NOTES',ph:'Rate limit: 10 req/s'}].map(({key,label,ph}) => (
          <div key={key} style={{marginBottom:12}}>
            <label className="label">{label}</label>
            {key==='notes' ? <textarea className="input" value={form[key]||''} onChange={set(key)} placeholder={ph} rows={2} style={{resize:'vertical'}} />
            : <input className="input" value={form[key]||''} onChange={set(key)} placeholder={ph} />}
          </div>
        ))}
        {err && <div style={{color:'var(--red)',fontFamily:'var(--font-mono)',fontSize:12,marginBottom:12}}>⚠ {err}</div>}
        <div style={{display:'flex',gap:8,justifyContent:'flex-end'}}>
          <button className="btn" onClick={onClose}>CANCEL</button>
          <button className="btn primary" onClick={submit} disabled={loading}>{loading?'SAVING...':target?'UPDATE':'CREATE'}</button>
        </div>
      </div>
    </div>
  )
}

function ScanModal({ target, onClose, onLaunch }) {
  const [mode, setMode] = useState('passive')
  const [tools, setTools] = useState([])
  const [selectedTools, setSelectedTools] = useState([])
  const [skipAI, setSkipAI] = useState(false)
  const [maxIter, setMaxIter] = useState(mode === 'passive' ? 20 : 40)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    fetch('/api/v1/tools/available').then(r=>r.json()).then(data => {
      const list = Object.entries(data).map(([name, info]) => ({name, ...info}))
      setTools(list)
      // Auto-select appropriate tools for the mode
      const defaults = list.filter(t => mode === 'passive' ? t.passive_safe : true).map(t => t.name)
      setSelectedTools(defaults.slice(0, mode === 'passive' ? 20 : 50))
    }).catch(() => {})
  }, [mode])

  const toggleTool = name => setSelectedTools(s => s.includes(name) ? s.filter(x=>x!==name) : [...s,name])

  const launch = async () => {
    setLoading(true)
    const config = { recon_tools: selectedTools.filter(n=>tools.find(t=>t.name===n&&t.phase==='recon')), vulnscan_tools: selectedTools.filter(n=>tools.find(t=>t.name===n&&t.phase==='vulnscan')), skip_ai: skipAI, ai_max_iterations: maxIter }
    try { await api.scans.create({ target_id: target.id, mode, config: JSON.stringify(config) }); onLaunch() }
    catch(e) { alert(e.message) } finally { setLoading(false) }
  }

  const byPhase = (phase) => tools.filter(t => t.phase === phase && (mode === 'passive' ? t.passive_safe : true))

  return (
    <div className="modal-overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal" style={{width:640,maxHeight:'85vh',overflow:'auto'}}>
        <div className="section-title" style={{marginBottom:12}}>// LAUNCH SCAN — {target.domain}</div>

        {/* Mode selector */}
        <div style={{marginBottom:20}}>
          <label className="label">SCAN MODE</label>
          <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:10}}>
            {[
              {id:'passive',icon:'🕵️',title:'PASSIVE',sub:'OSINT only — zero touch, stealth, no packets sent to target'},
              {id:'aggressive',icon:'⚔️',title:'AGGRESSIVE',sub:'Full exploit chain — active payloads, WAF bypass, all tools'},
            ].map(m => (
              <div key={m.id} onClick={()=>{setMode(m.id);setMaxIter(m.id==='passive'?20:40)}} style={{padding:14,cursor:'pointer',borderRadius:'var(--radius)',border:`2px solid ${mode===m.id?(m.id==='passive'?'var(--green)':'var(--red)'):'var(--border)'}`,background:mode===m.id?(m.id==='passive'?'var(--green-dim)':'var(--red-dim)'):'transparent',transition:'all 0.15s'}}>
                <div style={{fontSize:20,marginBottom:4}}>{m.icon}</div>
                <div style={{fontWeight:700,fontSize:13,fontFamily:'var(--font-ui)',color:mode===m.id?(m.id==='passive'?'var(--green)':'var(--red)'):'var(--text-primary)',marginBottom:4}}>{m.title}</div>
                <div style={{fontFamily:'var(--font-mono)',fontSize:10,color:'var(--text-muted)',lineHeight:1.5}}>{m.sub}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Tool selection by phase */}
        {['recon','vulnscan','exploit'].map(phase => {
          const phaseTools = byPhase(phase)
          if (phaseTools.length === 0) return null
          return (
            <div key={phase} style={{marginBottom:14}}>
              <label className="label">{phase.toUpperCase()} TOOLS ({phaseTools.filter(t=>selectedTools.includes(t.name)).length}/{phaseTools.length} selected)</label>
              <div style={{display:'flex',flexWrap:'wrap',gap:5}}>
                {phaseTools.map(t => {
                  const active = selectedTools.includes(t.name)
                  return (
                    <button key={t.name} onClick={()=>toggleTool(t.name)} title={t.description} style={{padding:'3px 9px',fontFamily:'var(--font-mono)',fontSize:10,cursor:'pointer',borderRadius:'var(--radius)',border:`1px solid ${active?'var(--accent)':'var(--border)'}`,background:active?'var(--accent-dim)':'transparent',color:active?'var(--accent)':'var(--text-muted)',transition:'all 0.1s'}}>
                      {t.name}
                    </button>
                  )
                })}
              </div>
            </div>
          )
        })}

        {tools.length === 0 && <div style={{fontFamily:'var(--font-mono)',fontSize:11,color:'var(--text-muted)',marginBottom:14}}>Loading installed tools...</div>}

        {/* AI settings */}
        <div style={{marginBottom:16,display:'flex',alignItems:'center',gap:12}}>
          <div>
            <label className="label">AI {mode==='passive'?'PASSIVE':'AGGRESSIVE'} AGENT</label>
            <button onClick={()=>setSkipAI(s=>!s)} style={{padding:'4px 12px',fontFamily:'var(--font-mono)',fontSize:11,cursor:'pointer',borderRadius:'var(--radius)',border:`1px solid ${!skipAI?'var(--green)':'var(--border)'}`,background:!skipAI?'var(--green-dim)':'transparent',color:!skipAI?'var(--green)':'var(--text-dim)'}}>
              {skipAI?'DISABLED':'ENABLED'}
            </button>
          </div>
          {!skipAI && (
            <div>
              <label className="label">MAX ITERATIONS</label>
              <input type="number" value={maxIter} onChange={e=>setMaxIter(+e.target.value)} min={5} max={80} style={{width:60,padding:'4px 8px',fontFamily:'var(--font-mono)',fontSize:12,background:'var(--bg-input)',border:'1px solid var(--border)',borderRadius:'var(--radius)',color:'var(--text-primary)',outline:'none'}} />
            </div>
          )}
        </div>

        <div style={{display:'flex',gap:8,justifyContent:'flex-end'}}>
          <button className="btn" onClick={onClose}>CANCEL</button>
          <button className={`btn ${mode==='passive'?'success':'danger'}`} onClick={launch} disabled={loading}>
            {loading ? 'LAUNCHING...' : `${mode==='passive'?'🕵️':'⚔️'} LAUNCH ${mode.toUpperCase()}`}
          </button>
        </div>
      </div>
    </div>
  )
}

export default function Targets() {
  const [targets, setTargets] = useState([])
  const [loading, setLoading] = useState(true)
  const [modal, setModal] = useState(null)
  const [selected, setSelected] = useState(null)
  const navigate = useNavigate()

  const load = () => { setLoading(true); api.targets.list().then(setTargets).catch(()=>{}).finally(()=>setLoading(false)) }
  useEffect(() => { load() }, [])

  const del = async t => { if (!confirm(`Delete ${t.domain}?`)) return; await api.targets.delete(t.id); load() }

  return (
    <div style={{padding:24,height:'100%',overflow:'auto'}}>
      <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:20}}>
        <div>
          <div style={{fontFamily:'var(--font-mono)',color:'var(--accent)',letterSpacing:2,fontSize:13}}>// TARGETS</div>
          <div style={{color:'var(--text-muted)',fontSize:12,marginTop:2}}>{targets.length} programs configured</div>
        </div>
        <button className="btn primary" onClick={()=>setModal('create')}>+ NEW TARGET</button>
      </div>
      {loading ? <div className="empty-state"><div style={{color:'var(--accent)'}}>⟳</div><div>LOADING...</div></div>
      : targets.length === 0 ? <div className="empty-state"><div style={{fontSize:28}}>◎</div><div>NO TARGETS</div></div>
      : <div style={{display:'grid',gap:12}}>
          {targets.map(t => (
            <div key={t.id} className="card" style={{padding:16}}>
              <div style={{display:'flex',alignItems:'flex-start',justifyContent:'space-between',gap:12}}>
                <div style={{flex:1}}>
                  <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:6}}>
                    <span style={{fontWeight:700,fontSize:16}}>{t.name}</span>
                    <span style={{fontFamily:'var(--font-mono)',fontSize:11,color:'var(--accent)',padding:'1px 8px',border:'1px solid var(--accent-dim)',borderRadius:2}}>{t.domain}</span>
                  </div>
                  <div style={{fontFamily:'var(--font-mono)',fontSize:11}}>
                    <span style={{color:'var(--text-muted)'}}>SCOPE: </span><span style={{color:'var(--green)'}}>{t.scope}</span>
                    {t.out_of_scope && <><span style={{color:'var(--text-muted)',marginLeft:12}}>OOS: </span><span style={{color:'var(--red)'}}>{t.out_of_scope}</span></>}
                  </div>
                </div>
                <div style={{display:'flex',gap:6,flexShrink:0}}>
                  <button className="btn success sm" onClick={()=>{setSelected(t);setModal('scan')}}>🕵️ PASSIVE</button>
                  <button className="btn danger sm" onClick={()=>{setSelected(t);setModal('scan')}}>⚔️ AGGR</button>
                  <button className="btn sm" onClick={()=>{setSelected(t);setModal('edit')}}>EDIT</button>
                  <button className="btn danger sm" onClick={()=>del(t)}>DEL</button>
                </div>
              </div>
            </div>
          ))}
        </div>}
      {(modal==='create'||modal==='edit') && <TargetModal target={modal==='edit'?selected:null} onClose={()=>{setModal(null);setSelected(null)}} onSave={()=>{setModal(null);setSelected(null);load()}} />}
      {modal==='scan' && selected && <ScanModal target={selected} onClose={()=>{setModal(null);setSelected(null)}} onLaunch={()=>{setModal(null);setSelected(null);navigate('/scans')}} />}
    </div>
  )
}
