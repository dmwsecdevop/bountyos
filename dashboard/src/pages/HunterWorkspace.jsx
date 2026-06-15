import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api'

const TABS = ['overview','graph','hypotheses','plan','validation','reports','quality','memory']
const STAGES = [
  ['OBSERVE','Scan evidence'], ['GRAPH','Connect assets'], ['HYPOTHESIZE','Predict bug classes'],
  ['PLAN','Rank next action'], ['VALIDATE','Minimal proof'], ['EVIDENCE','Redact + hash'],
  ['REPORT','Bounty-ready'], ['EVALUATE','Critic + verifier'], ['LEARN','Store utility'],
]
const COLORS = {target:'#00d4ff',asset:'#00ff9d',endpoint:'#ffd166',technology:'#bd93f9',finding:'#ff3b5c',hypothesis:'#ff8c42'}

function Metric({label,value,color='var(--accent)'}) {
  return <div className="hunter-metric"><span style={{color}}>{value ?? 0}</span><small>{label}</small></div>
}

function WorkflowRail({active=3}) {
  return <div className="hunter-rail">
    {STAGES.map(([title,sub],i)=><React.Fragment key={title}>
      <div className={`hunter-stage ${i<=active?'done':''} ${i===active?'active':''}`}>
        <b>{String(i+1).padStart(2,'0')}</b><div><strong>{title}</strong><small>{sub}</small></div>
      </div>{i<STAGES.length-1&&<div className={`hunter-link ${i<active?'done':''}`} />}
    </React.Fragment>)}
  </div>
}

function GraphView({graph}) {
  const nodes = graph?.nodes || [], edges = graph?.edges || []
  const layout = useMemo(()=>{
    const groups = {}
    nodes.forEach(n => (groups[n.node_type] ||= []).push(n))
    const order = ['target','asset','technology','endpoint','finding','hypothesis']
    const pos = {}
    order.forEach((type,col)=>{
      const arr=groups[type]||[]
      arr.forEach((n,row)=>{ pos[n.id]={x:90+col*175,y:70+row*70,type} })
    })
    return pos
  },[nodes])
  if(!nodes.length) return <div className="empty-state">RUN HUNTER WORKFLOW TO BUILD THE ATTACK GRAPH</div>
  const maxRows=Math.max(4,...Object.values(nodes.reduce((a,n)=>{a[n.node_type]=(a[n.node_type]||0)+1;return a},{})))
  const height=Math.max(420,100+maxRows*70)
  return <div className="hunter-graph-wrap">
    <svg viewBox={`0 0 1080 ${height}`} className="hunter-graph-svg">
      <defs><filter id="glow"><feGaussianBlur stdDeviation="4" result="c"/><feMerge><feMergeNode in="c"/><feMergeNode in="SourceGraphic"/></feMerge></filter></defs>
      {edges.map(e=>{const a=layout[e.source_node_id],b=layout[e.target_node_id]; if(!a||!b)return null;return <g key={e.id}><line x1={a.x} y1={a.y} x2={b.x} y2={b.y} className="graph-edge"/><text x={(a.x+b.x)/2} y={(a.y+b.y)/2-5} className="graph-relation">{e.relation}</text></g>})}
      {nodes.map(n=>{const p=layout[n.id];if(!p)return null;const color=COLORS[n.node_type]||'#7f8c8d';return <g key={n.id} transform={`translate(${p.x},${p.y})`} className="graph-node" filter="url(#glow)"><circle r="23" fill={`${color}22`} stroke={color}/><text textAnchor="middle" y="4" fill={color} fontSize="10">{n.node_type.slice(0,3).toUpperCase()}</text><text x="31" y="-2" fill="#d8f7ee" fontSize="11">{String(n.label).slice(0,25)}</text><text x="31" y="13" fill="#69838a" fontSize="9">risk {Math.round(n.risk_score||0)} · {Math.round((n.confidence||0)*100)}%</text></g>})}
    </svg>
  </div>
}

export default function HunterWorkspace(){
  const [scans,setScans]=useState([]),[scanId,setScanId]=useState(''),[data,setData]=useState(null)
  const [tab,setTab]=useState('overview'),[busy,setBusy]=useState(false),[msg,setMsg]=useState('')
  const [labs,setLabs]=useState([])
  const loadScans=()=>api.scans.list().then(x=>{setScans(x);if(!scanId&&x[0])setScanId(x[0].id)}).catch(e=>setMsg(e.message))
  const refresh=()=>scanId&&api.hunter.snapshot(scanId).then(setData).catch(e=>setMsg(e.message))
  useEffect(()=>{loadScans();api.hunter.labs().then(x=>setLabs(x.scenarios||[])).catch(()=>{})},[])
  useEffect(()=>{refresh()},[scanId])
  const run=async()=>{if(!scanId)return;setBusy(true);setMsg('Hunter agents are building the graph and hypotheses...');try{await api.hunter.run(scanId,{});await refresh();setMsg('Full Hacker Mindset workflow completed.')}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const makeValidation=async id=>{setBusy(true);try{await api.hunter.createValidation(id);await refresh();setTab('validation')}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const approve=async id=>{setBusy(true);try{await api.hunter.approveValidation(id,true);await refresh()}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const execute=async id=>{setBusy(true);try{await api.hunter.executeValidation(id,true);await refresh()}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const report=async()=>{setBusy(true);try{await api.hunter.generateReport(scanId,{});await refresh();setTab('reports')}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const evaluate=async()=>{if(!scanId)return;setBusy(true);setMsg('Critic and verifier are checking agent work against evidence...');try{await api.quality.evaluate(scanId,{});await refresh();setTab('quality');setMsg('Agent Quality Loop completed.')}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const retryEval=async id=>{setBusy(true);try{const r=await api.quality.retry(id);await refresh();setMsg(r.message||'Controlled retry processed.')}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const createLab=async id=>{setBusy(true);try{const r=await api.hunter.createLab(id,{});await loadScans();setScanId(r.scan_id);setData(r);setMsg(`Digital twin ${id} created.`)}catch(e){setMsg(e.message)}finally{setBusy(false)}}
  const g=data?.graph?.summary||{}, hyps=data?.hypotheses||[], plans=data?.plans||[], vals=data?.validations||[], reports=data?.reports||[], quality=data?.quality||{}, evals=quality?.evaluations||[], qsum=quality?.summary||{}, memory=data?.memory||{}, exp=data?.experience||[]
  const active=evals.length?8:reports.length?6:vals.some(v=>['likely','confirmed','approved'].includes(v.status))?5:vals.length?4:plans.length?3:hyps.length?2:g.node_count?1:0
  return <div className="hunter-page">
    <div className="hunter-hero">
      <div><div className="eyebrow">// FULL HACKER MINDSET ENGINE</div><h1>Autonomous Hunter Workspace</h1><p>Evidence → graph → hypotheses → adaptive plan → controlled proof → bounty report.</p></div>
      <div className="hunter-actions"><select value={scanId} onChange={e=>setScanId(e.target.value)} className="input"><option value="">Select scan</option>{scans.map(s=><option key={s.id} value={s.id}>{s.id.slice(0,8)} · {s.status} · {s.mode}</option>)}</select><button className="btn primary" disabled={!scanId||busy} onClick={run}>{busy?'AGENTS WORKING...':'🧠 RUN FULL HUNTER'}</button></div>
    </div>
    <WorkflowRail active={active}/>
    <div className="hunter-metrics"><Metric label="GRAPH NODES" value={g.node_count}/><Metric label="RELATIONS" value={g.edge_count} color="var(--purple)"/><Metric label="HYPOTHESES" value={hyps.length} color="var(--orange)"/><Metric label="PLANNED" value={plans.length} color="var(--yellow)"/><Metric label="VALIDATIONS" value={vals.length} color="var(--green)"/><Metric label="REPORTS" value={reports.length} color="var(--red)"/><Metric label="QUALITY" value={qsum.average_score?`${qsum.average_score}`:'—'} color="var(--green)"/></div>
    <div className="hunter-tabs">{TABS.map(t=><button key={t} className={tab===t?'active':''} onClick={()=>setTab(t)}>{t}</button>)}</div>
    {msg&&<div className="hunter-message">{msg}</div>}
    <div className="hunter-content">
      {tab==='overview'&&<div className="hunter-overview-grid">
        <section className="hunter-panel"><div className="panel-title">TOP HYPOTHESES</div>{hyps.slice(0,5).map(h=><div className="hyp-row" key={h.id}><div className="score-chip">{Math.round(h.priority_score)}</div><div><b>{h.title}</b><small>{h.bug_class} · confidence {Math.round(h.confidence*100)}%</small></div></div>)}{!hyps.length&&<div className="empty-state">No hypotheses yet.</div>}</section>
        <section className="hunter-panel"><div className="panel-title">NEXT BEST ACTIONS</div>{plans.slice(0,5).map(p=><div className="plan-row" key={p.id}><div><b>{p.action_name.replaceAll('_',' ')}</b><small>value {Math.round(p.expected_value*100)}% · effort {p.effort} · {p.approval_required?'approval':'safe'}</small></div><button className="btn sm" onClick={()=>makeValidation(p.id)}>PREPARE</button></div>)}{!plans.length&&<div className="empty-state">No adaptive plan yet.</div>}</section>
        <section className="hunter-panel lab-panel"><div className="panel-title">DIGITAL TWIN LABS</div>{labs.map(l=><div className="lab-row" key={l.id}><div><b>{l.name}</b><small>{l.description}</small></div><button className="btn sm success" onClick={()=>createLab(l.id)}>CREATE</button></div>)}</section>
        <section className="hunter-panel"><div className="panel-title">SHARED MEMORY</div><div className="memory-stats"><span>{memory.total||0}<small>records</small></span>{Object.entries(memory.by_agent||{}).slice(0,5).map(([k,v])=><span key={k}>{v}<small>{k.replaceAll('_',' ')}</small></span>)}</div></section>
        <section className="hunter-panel quality-overview"><div className="panel-title">AGENT QUALITY LOOP</div><div className="quality-hero"><div className="quality-dial">{qsum.average_score||0}<small>/100</small></div><div><b>{qsum.total||0} outputs evaluated</b><p>{qsum.needs_attention||0} need retry or review. Critic scores are evidence-grounded, not self-reported.</p><button className="btn sm success" onClick={evaluate}>RUN EVALUATION</button></div></div></section>
      </div>}
      {tab==='graph'&&<GraphView graph={data?.graph}/>} 
      {tab==='hypotheses'&&<div className="card-grid">{hyps.map(h=><article className="hunter-card" key={h.id}><div className="card-top"><span className="score-ring-mini">{Math.round(h.priority_score)}</span><span className={`badge ${h.bounty_value==='high'?'high':'medium'}`}>{h.bounty_value}</span></div><h3>{h.title}</h3><div className="meta">{h.bug_class} · confidence {Math.round(h.confidence*100)}% · {h.status}</div><p>{h.reasoning_summary}</p><div className="evidence-list">{(h.evidence||[]).slice(0,4).map((x,i)=><small key={i}>↳ {x}</small>)}</div></article>)}</div>}
      {tab==='plan'&&<div className="card-grid">{plans.map(p=><article className="hunter-card" key={p.id}><div className="card-top"><span className="score-ring-mini">{Math.round(p.expected_value*100)}</span><span className={`badge ${p.approval_required?'high':'low'}`}>{p.approval_required?'approval':'safe'}</span></div><h3>{p.action_name.replaceAll('_',' ')}</h3><div className="meta">effort {p.effort} · noise {p.noise} · {p.status}</div><p>{p.rationale}</p><button className="btn primary sm" onClick={()=>makeValidation(p.id)}>PREPARE VALIDATION</button></article>)}</div>}
      {tab==='validation'&&<div className="card-grid">{vals.map(v=><article className="hunter-card" key={v.id}><div className="card-top"><span className={`badge ${v.status==='confirmed'?'critical':v.status==='likely'?'high':v.status==='approved'?'low':'pending'}`}>{v.status}</span><span className="meta">budget {v.plan?.request_budget??0}</span></div><h3>{v.validation_type.replaceAll('_',' ')}</h3><p>{v.result_summary||v.plan?.stop_condition}</p><div className="button-row">{v.status==='awaiting_approval'&&<button className="btn danger sm" onClick={()=>approve(v.id)}>APPROVE</button>}{['planned','approved','awaiting_approval'].includes(v.status)&&<button className="btn primary sm" disabled={v.status==='awaiting_approval'} onClick={()=>execute(v.id)}>RUN CONTROLLED DRY-RUN</button>}</div></article>)}</div>}
      {tab==='reports'&&<div><div className="report-toolbar"><button className="btn primary" onClick={report}>📄 GENERATE BOUNTY REPORT</button></div><div className="card-grid">{reports.map(r=><article className="hunter-card report-card" key={r.id}><div className="card-top"><span className={`badge ${r.status==='ready'?'done':'pending'}`}>{r.status}</span><span className="quality">{r.quality_score}/100</span></div><h3>{r.title}</h3><p>{r.content?.executive_summary}</p><div className="button-row"><a className="btn sm" href={`/api/v1/hunter/reports/${r.id}/download/markdown`}>MARKDOWN</a><a className="btn sm" href={`/api/v1/hunter/reports/${r.id}/download/json`}>JSON</a><a className="btn sm" href={`/api/v1/hunter/reports/${r.id}/download/html`}>HTML</a></div></article>)}</div></div>}
      {tab==='quality'&&<div><div className="quality-toolbar"><div><b>AGENT QUALITY LOOP</b><small>Critic · verifier · confidence calibration · controlled retries</small></div><button className="btn success" onClick={evaluate}>🔄 EVALUATE ALL WORK</button></div><div className="quality-summary-grid"><Metric label="AVERAGE SCORE" value={qsum.average_score||0}/><Metric label="ACCEPTED" value={(qsum.by_status?.accepted||0)+(qsum.by_status?.accepted_with_warnings||0)} color="var(--green)"/><Metric label="NEEDS RETRY" value={qsum.by_status?.retry||0} color="var(--yellow)"/><Metric label="REJECTED" value={qsum.by_status?.rejected||0} color="var(--red)"/></div><div className="card-grid quality-grid">{evals.map(e=><article className={`hunter-card quality-card ${e.status}`} key={e.id}><div className="card-top"><span className="score-ring-mini">{e.overall_score}</span><span className={`badge ${e.status==='accepted'?'done':e.status==='accepted_with_warnings'?'low':e.status==='retry'?'pending':'critical'}`}>{e.status.replaceAll('_',' ')}</span></div><h3>{e.task_type} · {e.producer_agent.replaceAll('_',' ')}</h3><div className="meta">confidence {Math.round((e.calibrated_confidence||0)*100)}% · retry {e.retry_count||0}/2</div><div className="quality-bars">{[['Evidence',e.evidence_quality],['Accuracy',e.accuracy],['Reproduce',e.reproducibility],['Impact',e.impact_confidence],['Efficiency',e.efficiency],['Safety',e.safety]].map(([k,v])=><div key={k}><span>{k}<b>{v}</b></span><i><em style={{width:`${v}%`}}/></i></div>)}</div>{(e.findings||[]).slice(0,3).map((x,i)=><p className="quality-finding" key={i}>⚠ {x}</p>)}{(e.recommendations||[]).slice(0,2).map((x,i)=><p className="quality-rec" key={i}>↳ {x}</p>)}{['retry','rejected'].includes(e.status)&&<button className="btn primary sm" onClick={()=>retryEval(e.id)}>CONTROLLED RETRY</button>}</article>)}{!evals.length&&<div className="empty-state">Run the Agent Quality Loop to evaluate hypotheses, plans, validation results and reports.</div>}</div></div>}
      {tab==='memory'&&<div className="memory-feed">{(memory.recent||[]).map(m=><div className="memory-item" key={m.id}><span>{m.agent}</span><b>{m.kind}</b><p>{m.content}</p><small>{new Date(m.created_at).toLocaleString()}</small></div>)}{exp.slice(0,30).map(e=><div className="memory-item experience" key={e.id}><span>experience</span><b>{e.action}</b><p>{e.result} · utility {e.utility}</p></div>)}</div>}
    </div>
  </div>
}
