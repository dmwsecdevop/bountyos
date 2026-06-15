import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api'

const card = { background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:14 }
const mono = { fontFamily:'var(--font-mono)' }

function Pill({ children, color='var(--accent)' }) {
  return <span style={{...mono, fontSize:10, color, border:`1px solid ${color}55`, borderRadius:2, padding:'2px 7px', background:`${color}12`}}>{children}</span>
}

export default function ProgramRadar() {
  const [snapshot, setSnapshot] = useState(null)
  const [programs, setPrograms] = useState([])
  const [sources, setSources] = useState([])
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState(null)
  const [query, setQuery] = useState('')
  const [bountyOnly, setBountyOnly] = useState(false)
  const [importing, setImporting] = useState('')
  const [opportunities, setOpportunities] = useState([])
  const [selectedOpportunity, setSelectedOpportunity] = useState(null)

  const refresh = async () => {
    const [snap, list, src] = await Promise.all([
      api.programs.snapshot().catch(()=>null),
      api.programs.list({ limit: 200, ...(bountyOnly ? { bounty_only: true } : {}) }).catch(()=>[]),
      api.programs.sources().catch(()=>({sources:[]})),
    ])
    setSnapshot(snap)
    setPrograms(list)
    setSources(src.sources || [])
  }

  useEffect(() => { refresh() }, [bountyOnly])

  const runCheck = async () => {
    setBusy(true)
    try {
      const res = await api.programs.check(500)
      setResult(res)
      await refresh()
    } catch(e) {
      setResult({ error: e.message })
    } finally { setBusy(false) }
  }

  const findEasyPrograms = async () => {
    setBusy(true)
    try {
      const res = await api.programs.recommendEasy({ limit: 8 })
      setOpportunities(res.recommendations || [])
      setSelectedOpportunity((res.recommendations || [])[0] || null)
      setResult(res)
    } catch(e) {
      setResult({ error: e.message })
    } finally { setBusy(false) }
  }

  const expandProgram = async (p) => {
    try {
      const res = await api.programs.opportunity(p.id)
      setSelectedOpportunity(res)
    } catch(e) {
      setResult({ error: e.message })
    }
  }

  const importTargets = async (id) => {
    setImporting(id)
    try {
      const res = await api.programs.addTargets(id, 25)
      setResult(res)
      await refresh()
    } catch(e) {
      setResult({ error: e.message })
    } finally { setImporting('') }
  }

  const filtered = useMemo(() => {
    const q = query.toLowerCase().trim()
    if (!q) return programs
    return programs.filter(p => `${p.name} ${p.platform} ${p.url} ${p.domains_json}`.toLowerCase().includes(q))
  }, [programs, query])

  return <div style={{padding:20, display:'flex', flexDirection:'column', gap:14}}>
    <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', gap:12}}>
      <div>
        <div style={{...mono, color:'var(--accent)', letterSpacing:2, fontSize:14}}>// BOUNTY PROGRAM RADAR</div>
        <div style={{fontSize:12, color:'var(--text-muted)', marginTop:4}}>Automatically checks online/public bug bounty program feeds, tracks scope changes, and imports domains as targets.</div>
      </div>
      <div style={{display:'flex', gap:8, alignItems:'center'}}>
        <Pill color='var(--green)'>{snapshot?.total_programs || 0} PROGRAMS</Pill>
        <Pill color='var(--yellow)'>{snapshot?.bounty_programs || 0} BOUNTY</Pill>
      </div>
    </div>

    <div style={{display:'grid', gridTemplateColumns:'1fr .85fr', gap:14}}>
      <div style={card}>
        <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>PROGRAM CHECKER</div>
        <div style={{display:'flex', gap:8, flexWrap:'wrap', alignItems:'center'}}>
          <button onClick={runCheck} disabled={busy} className='btn-primary' style={{opacity:busy?.6:1}}>{busy ? 'CHECKING ONLINE...' : 'CHECK ONLINE PROGRAMS'}</button>
          <button onClick={refresh} className='btn'>REFRESH</button>
          <button onClick={findEasyPrograms} disabled={busy} className='btn success'>FIND EASY MONEY TARGETS</button>
          <label style={{display:'flex', gap:6, alignItems:'center', color:'var(--text-dim)', fontSize:12, ...mono}}>
            <input type='checkbox' checked={bountyOnly} onChange={e=>setBountyOnly(e.target.checked)} /> bounty only
          </label>
        </div>
        <div style={{height:1, background:'var(--border)', margin:'12px 0'}} />
        <div style={{display:'grid', gridTemplateColumns:'repeat(4,1fr)', gap:8}}>
          <Stat label='Total' value={snapshot?.total_programs || 0} />
          <Stat label='Bounty' value={snapshot?.bounty_programs || 0} />
          <Stat label='Sources' value={sources.length} />
          <Stat label='Visible' value={filtered.length} />
        </div>
        {result && <RadarResult result={result} />}
      </div>

      <div style={card}>
        <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>SOURCES</div>
        <div style={{display:'flex', flexDirection:'column', gap:8}}>
          {sources.map((s, i) => <div key={i} style={{background:'var(--bg-input)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:9}}>
            <div style={{display:'flex', justifyContent:'space-between', gap:8}}><b style={{fontSize:12, color:'var(--text-primary)'}}>{s.name}</b><Pill>{s.type}</Pill></div>
            <div style={{...mono, fontSize:10, color:'var(--text-muted)', marginTop:6, wordBreak:'break-all'}}>{s.url}</div>
          </div>)}
          {!sources.length && <div style={{color:'var(--text-muted)', fontSize:12}}>No sources configured.</div>}
        </div>
        <div style={{fontSize:11, color:'var(--text-muted)', marginTop:12, lineHeight:1.6}}>Set <code>BOUNTYOS_PROGRAM_FEEDS</code> to comma-separated JSON feed URLs to add your own HackerOne/Bugcrowd/Intigriti/YesWeHack exports or private invite feeds.</div>
      </div>
    </div>


    <div style={{display:'grid', gridTemplateColumns:'1.1fr .9fr', gap:14}}>
      <div style={{...card, position:'relative', overflow:'hidden'}} className='animated-card opportunity-card'>
        <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:10}}>
          <div style={{...mono, color:'var(--green)', fontSize:12}}>OPPORTUNITY SCORER // EASY MONEY FINDER</div>
          <Pill color='var(--green)'>{opportunities.length || 'READY'} RANKED</Pill>
        </div>
        <div style={{fontSize:12, color:'var(--text-muted)', marginBottom:10}}>Ranks programs by reward potential, scope quality, API/business-logic surface, and estimated effort. No AI can guarantee a bounty; this only improves target selection.</div>
        <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fit,minmax(220px,1fr))', gap:8}}>
          {opportunities.map(o => <button key={o.program_id} onClick={()=>setSelectedOpportunity(o)} className='opportunity-mini-card' style={{textAlign:'left'}}>
            <div style={{display:'flex', justifyContent:'space-between', gap:8}}><b>{o.name}</b><span>{o.score}/100</span></div>
            <div style={{...mono, fontSize:10, color:'var(--text-muted)', marginTop:4}}>{o.platform} · {o.difficulty} · {o.money_potential}</div>
          </button>)}
          {!opportunities.length && <div style={{color:'var(--text-muted)', fontSize:12}}>Click “Find Easy Money Targets” after program sync/check.</div>}
        </div>
      </div>
      <OpportunityDetail data={selectedOpportunity} />
    </div>

    <div style={card}>
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:10, gap:10}}>
        <div style={{...mono, color:'var(--accent)', fontSize:12}}>PROGRAMS</div>
        <input value={query} onChange={e=>setQuery(e.target.value)} placeholder='filter programs/domains/platforms...' style={{background:'var(--bg-input)', border:'1px solid var(--border)', color:'var(--text-primary)', borderRadius:'var(--radius)', padding:'7px 9px', minWidth:260, ...mono, fontSize:11}} />
      </div>
      <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(310px, 1fr))', gap:10}}>
        {filtered.map(p => <ProgramCard key={p.id} p={p} importing={importing===p.id} onImport={()=>importTargets(p.id)} onExpand={()=>expandProgram(p)} />)}
        {!filtered.length && <div style={{color:'var(--text-muted)', fontSize:12}}>No programs yet. Click “Check online programs”.</div>}
      </div>
    </div>
  </div>
}

function RadarResult({ result }) {
  const summary = result?.summary || result
  const status = summary?.status || (summary?.errors?.length ? 'partial' : 'healthy')
  const color = status === 'healthy' ? 'var(--green)' : status === 'partial' ? 'var(--yellow)' : 'var(--red)'
  return <div style={{marginTop:12, background:'var(--bg-input)', border:`1px solid ${color}66`, borderRadius:'var(--radius)', padding:10}}>
    <div style={{display:'flex', justifyContent:'space-between', gap:8, alignItems:'center'}}>
      <Pill color={color}>{String(status).toUpperCase()}</Pill>
      <span style={{...mono, fontSize:10, color:'var(--text-muted)'}}>{summary?.successful_sources || 0}/{summary?.checked_sources || 0} sources online</span>
    </div>
    {(summary?.error_details || []).map((d,i) => <div key={i} style={{marginTop:8, padding:8, border:'1px solid var(--border)', borderRadius:'var(--radius)'}}>
      <div style={{...mono, fontSize:10, color:d.code === 'rate_limited' ? 'var(--yellow)' : 'var(--red)'}}>{String(d.code || 'error').toUpperCase()}</div>
      <div style={{fontSize:11, color:'var(--text-dim)', marginTop:4}}>{d.message}</div>
      {d.retry_after_seconds != null && <div style={{fontSize:10, color:'var(--yellow)', marginTop:4}}>Retry suggested in about {d.retry_after_seconds} seconds.</div>}
    </div>)}
    {!summary?.error_details?.length && <pre style={{margin:'8px 0 0', maxHeight:150, overflow:'auto', whiteSpace:'pre-wrap', wordBreak:'break-word', color:'var(--text-dim)', fontSize:11}}>{JSON.stringify(summary, null, 2)}</pre>}
    {result?.preserved_existing_data && <div style={{fontSize:10, color:'var(--text-muted)', marginTop:8}}>Existing stored programs were preserved while the source was unavailable.</div>}
  </div>
}

function Stat({ label, value }) {
  return <div style={{background:'var(--bg-input)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:10}}>
    <div style={{...mono, color:'var(--text-muted)', fontSize:10}}>{label}</div>
    <div style={{...mono, color:'var(--accent)', fontSize:18, marginTop:3}}>{value}</div>
  </div>
}

function ProgramCard({ p, onImport, importing, onExpand }) {
  let domains = []
  try { domains = JSON.parse(p.domains_json || '[]') } catch {}
  return <div style={{background:'var(--bg-input)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:12, display:'flex', flexDirection:'column', gap:8}}>
    <div style={{display:'flex', justifyContent:'space-between', gap:8, alignItems:'flex-start'}}>
      <div>
        <div style={{color:'var(--text-primary)', fontWeight:700, fontSize:13}}>{p.name}</div>
        <div style={{...mono, color:'var(--text-muted)', fontSize:10, marginTop:3}}>{p.platform} · score {p.value_score}</div>
      </div>
      <Pill color={p.offers_bounty ? 'var(--green)' : 'var(--text-muted)'}>{p.offers_bounty ? 'BOUNTY' : 'VDP'}</Pill>
    </div>
    {p.url && <a href={p.url} target='_blank' rel='noreferrer' style={{...mono, color:'var(--accent)', fontSize:10, wordBreak:'break-all'}}>{p.url}</a>}
    <div style={{display:'flex', gap:5, flexWrap:'wrap'}}>
      {domains.slice(0, 8).map(d => <span key={d} style={{...mono, fontSize:10, color:'var(--text-dim)', border:'1px solid var(--border)', borderRadius:2, padding:'2px 5px'}}>{d}</span>)}
      {domains.length > 8 && <span style={{...mono, fontSize:10, color:'var(--text-muted)'}}>+{domains.length-8} more</span>}
    </div>
    <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginTop:4}}>
      <span style={{...mono, fontSize:10, color:'var(--text-muted)'}}>last seen {(p.last_seen_at || '').replace('T',' ').slice(0,16)}</span>
      <div style={{display:'flex', gap:6}}><button onClick={onExpand} className='btn' style={{fontSize:10, padding:'5px 8px'}}>EXPAND</button><button onClick={onImport} disabled={importing} className='btn' style={{fontSize:10, padding:'5px 8px'}}>{importing ? 'IMPORTING...' : 'ADD TARGETS'}</button></div>
    </div>
  </div>
}


function OpportunityDetail({ data }) {
  if (!data) return <div style={{...card, minHeight:180}} className='animated-card'>
    <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>EXPANDED PROGRAM INTELLIGENCE</div>
    <div style={{color:'var(--text-muted)', fontSize:12}}>Select a ranked program or click EXPAND on any program to see difficulty, money potential, bug classes, reasons, warnings, and first moves.</div>
  </div>
  return <div style={{...card, position:'relative', overflow:'hidden'}} className='animated-card selected-opportunity'>
    <div style={{display:'flex', justifyContent:'space-between', gap:10, alignItems:'flex-start'}}>
      <div>
        <div style={{...mono, color:'var(--accent)', fontSize:12}}>EXPANDED PROGRAM INTELLIGENCE</div>
        <div style={{fontWeight:800, fontSize:18, marginTop:6}}>{data.name}</div>
        <div style={{...mono, color:'var(--text-muted)', fontSize:10}}>{data.platform} · {data.status}</div>
      </div>
      <div className='score-ring'><span>{data.score}</span><small>/100</small></div>
    </div>
    <div style={{display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:8, marginTop:12}}>
      <Stat label='Difficulty' value={data.difficulty} />
      <Stat label='Money' value={data.money_potential} />
      <Stat label='Effort' value={data.effort} />
    </div>
    <div style={{fontSize:12, color:'var(--text-dim)', marginTop:12, lineHeight:1.6}}>{data.summary}</div>
    <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:10, marginTop:12}}>
      <ListBlock title='WHY GOOD' items={data.reasons || []} color='var(--green)' />
      <ListBlock title='WARNINGS' items={data.warnings || []} color='var(--yellow)' />
    </div>
    <ListBlock title='BEST BUG CLASSES' items={data.best_bug_classes || []} color='var(--accent)' compact />
    <ListBlock title='FIRST MOVES' items={data.recommended_first_moves || []} color='var(--purple)' />
  </div>
}

function ListBlock({ title, items, color, compact=false }) {
  return <div style={{marginTop:compact?10:0}}>
    <div style={{...mono, color, fontSize:10, marginBottom:6}}>{title}</div>
    <div style={{display:'flex', flexDirection:compact?'row':'column', flexWrap:'wrap', gap:5}}>
      {(items || []).slice(0, compact?8:6).map((x,i)=><span key={i} style={{...mono, fontSize:10, color:'var(--text-dim)', border:'1px solid var(--border)', borderRadius:2, padding:'3px 6px', background:'rgba(255,255,255,.02)'}}>{x}</span>)}
      {!items?.length && <span style={{color:'var(--text-muted)', fontSize:11}}>No signal yet.</span>}
    </div>
  </div>
}
