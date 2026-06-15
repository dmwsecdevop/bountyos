import React, {useEffect, useMemo, useRef, useState} from 'react';

const API = '/api/v1';

async function request(path, options={}){
  const res = await fetch(API + path, {
    headers: {'Content-Type':'application/json', ...(options.headers||{})},
    ...options,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = {raw:text}; }
  if(!res.ok) throw new Error((data && (data.detail || data.error || data.message)) || res.statusText);
  return data;
}

const empty = [];
const statusColor = (s='') => {
  s = String(s).toLowerCase();
  if(s.includes('done') || s.includes('complete') || s.includes('online')) return 'var(--ok)';
  if(s.includes('run') || s.includes('pending') || s.includes('created')) return 'var(--warn)';
  if(s.includes('fail') || s.includes('error') || s.includes('off')) return 'var(--bad)';
  return 'var(--muted)';
};

function Pill({children, tone='accent'}){
  return <span className={`pill ${tone}`}>{children}</span>;
}
function Card({title, action, children, className=''}){
  return <section className={`card ${className}`}>
    <div className="card-head"><span>{title}</span>{action}</div>
    {children}
  </section>;
}
function Stat({label, value, tone='accent'}){
  return <div className="stat"><b className={tone}>{value}</b><span>{label}</span></div>;
}
function fmtDate(s){ return s ? String(s).replace('T',' ').slice(0,19) : '—'; }
function safeJson(x){ try { return JSON.stringify(x,null,2); } catch { return String(x); } }

function useDashboardData(){
  const [data,setData]=useState({live:null, targets:[], scans:[], findings:[], runners:null, models:null, upgrades:null});
  const [err,setErr]=useState('');
  const refresh = async()=>{
    try{
      const [live, targets, scans, findings, runners, models, upgrades] = await Promise.all([
        request('/live/snapshot').catch(()=>null),
        request('/targets/').catch(()=>empty),
        request('/scans/').catch(()=>empty),
        request('/findings/').catch(()=>empty),
        request('/runners/capabilities').catch(()=>null),
        request('/ai/models').catch(()=>null),
        request('/upgrades/').catch(()=>null),
      ]);
      setData({live, targets, scans, findings, runners, models, upgrades});
      setErr('');
    }catch(e){ setErr(e.message); }
  };
  useEffect(()=>{ refresh(); const id=setInterval(refresh,5000); return()=>clearInterval(id); },[]);
  return {...data, err, refresh};
}

function HunterChat({targets, scans, refresh}){
  const [text,setText]=useState('Paste a bug bounty target page or type: run passive scan');
  const [targetId,setTargetId]=useState('');
  const [scanId,setScanId]=useState('');
  const [approve,setApprove]=useState(false);
  const [busy,setBusy]=useState(false);
  const [messages,setMessages]=useState([
    {role:'system', text:'Hunter Brain online. Paste a target/program page, ask for recon, review findings, or trigger scans. Gemini/Vertex model routing is preferred; no Claude workflow required.'}
  ]);
  const [extracted,setExtracted]=useState(null);
  const bottom=useRef(null);
  useEffect(()=>bottom.current?.scrollIntoView({behavior:'smooth'}),[messages, extracted]);

  const add=(role,msg,obj)=>setMessages(m=>[...m,{role,text:msg,obj,ts:new Date().toISOString()}].slice(-30));

  const extract = async()=>{
    if(!text.trim()) return;
    setBusy(true); add('user', text);
    try{
      const res = await request('/ai/extract-target-page',{method:'POST',body:JSON.stringify({text})});
      setExtracted(res);
      add('assistant', res.summary || 'Extracted target intelligence.', res);
    }catch(e){ add('assistant','Extraction failed: '+e.message); }
    finally{setBusy(false); await refresh?.();}
  };

  const command = async()=>{
    if(!text.trim()) return;
    setBusy(true); add('user', text);
    try{
      const res = await request('/agent/command',{method:'POST',body:JSON.stringify({
        transcript:text,
        selected_target_id:targetId || null,
        selected_scan_id:scanId || null,
        approve,
        source:'v6_command_center'
      })});
      add('assistant', res?.act?.message || res?.response || res?.message || 'Command executed.', res);
    }catch(e){ add('assistant','Command failed: '+e.message); }
    finally{setBusy(false); setApprove(false); await refresh?.();}
  };

  const createTarget = async()=>{
    if(!extracted) return;
    const domain = (extracted.in_scope_domains||[])[0] || extracted.primary_domain || '';
    if(!domain){ add('assistant','No domain found to create a target.'); return; }
    setBusy(true);
    try{
      const res = await request('/targets/',{method:'POST',body:JSON.stringify({
        name: extracted.program_name || domain,
        domain,
        scope: (extracted.in_scope_domains||[]).join('\n') || domain,
        out_of_scope: (extracted.out_of_scope||[]).join('\n'),
        notes: extracted.rules_summary || 'Imported from Hunter Brain pasted page.'
      })});
      setTargetId(res.id);
      add('assistant',`Target created: ${res.name || res.domain}`, res);
    }catch(e){ add('assistant','Create target failed: '+e.message); }
    finally{setBusy(false); await refresh?.();}
  };

  const startScan = async(mode='passive')=>{
    if(!targetId){ add('assistant','Select or create a target first.'); return; }
    setBusy(true);
    try{
      const cfg = {execution_mode:'remote', source:'v6_command_center', profile: extracted?.recommended_profile || 'recon', skip_ai:false, skip_hunter:false};
      const res = await request('/scans/',{method:'POST',body:JSON.stringify({target_id:targetId, mode, config:JSON.stringify(cfg)})});
      setScanId(res.id);
      add('assistant',`${mode} scan started: ${res.id.slice(0,8)}`, res);
    }catch(e){ add('assistant','Start scan failed: '+e.message); }
    finally{setBusy(false); await refresh?.();}
  };

  return <Card title="HUNTER BRAIN // AI CHAT AGENT" className="chat-card" action={<><Pill>Gemini/Vertex</Pill><Pill tone="green">Command Mode</Pill></>}>
    <div className="select-row">
      <select value={targetId} onChange={e=>setTargetId(e.target.value)}>
        <option value="">Select target</option>{targets.map(t=><option key={t.id} value={t.id}>{t.name||t.domain} — {t.domain}</option>)}
      </select>
      <select value={scanId} onChange={e=>setScanId(e.target.value)}>
        <option value="">Select scan</option>{scans.map(s=><option key={s.id} value={s.id}>{s.id.slice(0,8)} — {s.status}/{s.phase}</option>)}
      </select>
    </div>
    <div className="chat-log">
      {messages.map((m,i)=><div key={i} className={`msg ${m.role}`}><b>{m.role}</b><p>{m.text}</p>{m.obj&&<details><summary>details</summary><pre>{safeJson(m.obj)}</pre></details>}</div>)}
      <div ref={bottom}/>
    </div>
    {extracted && <div className="extract-box">
      <div className="extract-grid">
        <Stat label="in-scope" value={(extracted.in_scope_domains||[]).length}/>
        <Stat label="out-of-scope" value={(extracted.out_of_scope||[]).length} tone="warn"/>
        <Stat label="profile" value={extracted.recommended_profile || 'recon'} tone="green"/>
        <Stat label="confidence" value={`${Math.round((extracted.confidence||0.6)*100)}%`}/>
      </div>
      <div className="chips">{(extracted.technologies||[]).slice(0,12).map(x=><Pill key={x}>{x}</Pill>)}</div>
      <div className="actions"><button onClick={createTarget}>CREATE TARGET</button><button onClick={()=>startScan('passive')}>START PASSIVE</button><button onClick={()=>startScan('aggressive')} className="danger">FULL SEND</button></div>
    </div>}
    <textarea value={text} onChange={e=>setText(e.target.value)} placeholder="Paste a HackerOne/Bugcrowd/Intigriti page, scope text, or command..." />
    <div className="actions">
      <button onClick={extract} disabled={busy}>EXTRACT TARGET PAGE</button>
      <button onClick={command} disabled={busy} className="primary">RUN HUNTER COMMAND</button>
      <label className="check"><input type="checkbox" checked={approve} onChange={e=>setApprove(e.target.checked)}/> approve active action</label>
    </div>
  </Card>;
}

function RunnerPanel({runners, models}){
  const online = runners?.online || [];
  const r = online[0];
  return <Card title="RUNNERS + AI MODELS" action={<Pill tone={online.length?'green':'red'}>{online.length?'ONLINE':'OFFLINE'}</Pill>}>
    <div className="runner-box">
      <Stat label="online runners" value={online.length} tone={online.length?'green':'bad'}/>
      <Stat label="tools" value={r?.tool_count || Object.keys(r?.tools||{}).length || 0}/>
      <Stat label="mode" value={runners?.current_mode || 'hybrid'}/>
      <Stat label="AI" value={models?.provider || 'vertex'} tone="green"/>
    </div>
    {r && <div className="kv"><span>Name</span><b>{r.name}</b><span>Host</span><b>{r.hostname}</b><span>Seen</span><b>{fmtDate(r.last_seen_at)}</b></div>}
    <div className="chips">{Object.keys(r?.tools||{}).slice(0,35).map(t=><Pill key={t}>{t}</Pill>)}</div>
    <pre className="mini-pre">{safeJson(models || {provider:'vertex', main_model:'gemini configurable by env'})}</pre>
  </Card>;
}

function TargetsPanel({targets}){return <Card title="TARGETS"><div className="list">{targets.slice(0,10).map(t=><div className="row" key={t.id}><div><b>{t.name||t.domain}</b><span>{t.domain}</span></div><Pill>{(t.scope||'').split('\n').filter(Boolean).length || 1} scope</Pill></div>)}{!targets.length&&<div className="empty">No targets yet. Paste a program page into Hunter Brain.</div>}</div></Card>}
function ScansPanel({scans}){return <Card title="LIVE SCANS"><div className="list">{scans.slice(0,10).map(s=><div className="row" key={s.id}><div><b>{s.id.slice(0,8)}</b><span>{s.mode} · {s.phase} · {fmtDate(s.created_at)}</span></div><Pill tone={String(s.status).includes('done')?'green':String(s.status).includes('fail')?'red':'warn'}>{s.status}</Pill></div>)}{!scans.length&&<div className="empty">No scans yet.</div>}</div></Card>}
function FindingsPanel({findings}){return <Card title="FINDINGS"><div className="list">{findings.slice(0,12).map(f=><div className="row finding" key={f.id}><div><b>{f.title}</b><span>{f.tool || 'unknown'} · {fmtDate(f.created_at)}</span></div><Pill tone={['critical','high'].includes(String(f.severity).toLowerCase())?'red':String(f.severity).toLowerCase()==='medium'?'warn':'green'}>{f.severity}</Pill></div>)}{!findings.length&&<div className="empty">No findings yet.</div>}</div></Card>}

function HunterBrainPanel({live, upgrades}){
  const events = [...(live?.live_events||[]), ...(live?.recent_scan_events||[]).map(e=>({type:e.level, payload:e, created_at:e.created_at}))].slice(-80).reverse();
  return <Card title="HUNTER BRAIN // LIVE EVENT STREAM" action={<Pill>ORTA Loop</Pill>}>
    <div className="brain-steps"><span>Observe</span><span>Reason</span><span>Think</span><span>Act</span><span>Learn</span></div>
    <div className="event-feed">{events.slice(0,40).map((e,i)=><div key={i} className="event"><span>{fmtDate(e.created_at)}</span><b>{e.type||e.level||'event'}</b><p>{e.payload?.message || e.message || e.payload?.action || JSON.stringify(e.payload||e).slice(0,180)}</p></div>)}{!events.length&&<div className="empty">Waiting for events...</div>}</div>
    {upgrades && <pre className="mini-pre">{safeJson(upgrades)}</pre>}
  </Card>
}

function KnowledgePanel(){
  const [stats,setStats]=useState(null);
  useEffect(()=>{request('/knowledge/stats').then(setStats).catch(()=>setStats({status:'not installed yet'}));},[]);
  return <Card title="PERSISTENT KNOWLEDGE GRAPH" action={<Pill tone="purple">Cross-Scan Memory</Pill>}>
    <div className="runner-box"><Stat label="techniques" value={stats?.total_techniques ?? 0}/><Stat label="chains" value={stats?.total_chains ?? 0}/><Stat label="attempts" value={stats?.total_attempts ?? 0}/><Stat label="success rate" value={stats?.overall_success_rate ?? 0}/></div>
    <div className="graph-placeholder"><div>JWT</div><span></span><div>NodeJS</div><span></span><div>Misconfig</div><span></span><div>Report</div></div>
  </Card>
}

function ProgramEarningsPanel({live}){
  const programs = live?.recent_programs || [];
  const accounts = live?.bounty_accounts || [];
  return <Card title="PROGRAM RADAR + EARNINGS"><div className="runner-box"><Stat label="programs" value={programs.length}/><Stat label="accounts" value={accounts.length}/><Stat label="month" value="$0" tone="green"/><Stat label="ROI" value="learn"/></div><div className="list compact">{programs.slice(0,8).map(p=><div className="row" key={p.id}><div><b>{p.name}</b><span>{p.platform} · score {p.value_score}</span></div><Pill tone={p.offers_bounty?'green':'warn'}>{p.offers_bounty?'bounty':'vdp'}</Pill></div>)}{!programs.length&&<div className="empty">Sync bounty accounts or run Program Radar.</div>}</div></Card>
}

export default function App(){
  const {live, targets, scans, findings, runners, models, upgrades, err, refresh} = useDashboardData();
  const recentScans = live?.recent_scans || scans || [];
  const recentFindings = live?.recent_findings || findings || [];
  const severity = useMemo(()=>recentFindings.reduce((a,f)=>{const s=String(f.severity||'info').toLowerCase();a[s]=(a[s]||0)+1;return a;},{}),[recentFindings]);
  return <div className="app-shell">
    <div className="grid-bg" />
    <header className="topbar"><div><h1>BOUNTYOS v6</h1><p>Gemini Command Center · Hunter Brain · Autonomous Bug Bounty OS</p></div><div className="top-pills"><Pill tone="green">Vertex/Gemini</Pill><Pill>Hybrid Runner</Pill><Pill tone={err?'red':'green'}>{err?'API WARN':'API LIVE'}</Pill></div></header>
    <main className="layout">
      <section className="hero"><HunterChat targets={targets||[]} scans={recentScans||[]} refresh={refresh}/><RunnerPanel runners={runners} models={models}/></section>
      <section className="metrics"><Stat label="targets" value={(targets||[]).length}/><Stat label="scans" value={(recentScans||[]).length}/><Stat label="findings" value={(recentFindings||[]).length}/><Stat label="critical/high" value={(severity.critical||0)+(severity.high||0)} tone="bad"/></section>
      <section className="three"><TargetsPanel targets={targets||[]}/><ScansPanel scans={recentScans||[]}/><FindingsPanel findings={recentFindings||[]}/></section>
      <section className="two"><HunterBrainPanel live={live} upgrades={upgrades}/><KnowledgePanel/></section>
      <section className="two"><ProgramEarningsPanel live={live}/><Card title="LIVE TERMINAL"><div className="terminal"><p>$ hunter brain ready</p><p>$ paste target page → extract scope → create target → scan → report</p><p>$ use approved actions for active testing</p></div></Card></section>
    </main>
  </div>;
}
