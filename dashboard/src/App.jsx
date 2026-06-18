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
const fmtDate = s => s ? String(s).replace('T',' ').slice(0,19) : '—';
const safeJson = x => { try { return JSON.stringify(x,null,2); } catch { return String(x); } };
const clip = (value, length=150) => {
  const text = typeof value === 'string' ? value : safeJson(value);
  return text.length > length ? `${text.slice(0,length).trim()}…` : text;
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
function DebugDetails({value, label='Show details'}){
  if(value == null) return null;
  return <details className="debug-details"><summary>{label}</summary><pre className="mini-pre">{safeJson(value)}</pre></details>;
}

function useDashboardData(){
  const [data,setData]=useState({live:null, targets:[], scans:[], findings:[], runners:null, models:null, upgrades:null});
  const [err,setErr]=useState('');
  const refresh = async()=>{
    try{
      const [live, targets, scans, findings, runners, models, upgrades] = await Promise.all([
        request('/live/snapshot').catch(()=>null), request('/targets/').catch(()=>empty),
        request('/scans/').catch(()=>empty), request('/findings/').catch(()=>empty),
        request('/runners/capabilities').catch(()=>null), request('/ai/models').catch(()=>null),
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
  const [text,setText]=useState('');
  const [targetId,setTargetId]=useState('');
  const [scanId,setScanId]=useState('');
  const [approve,setApprove]=useState(false);
  const [busy,setBusy]=useState(false);
  const [messages,setMessages]=useState([
    {role:'system', text:'Hunter Brain online. Select a target, ask for recon, or paste a program page for scope extraction.'}
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
      setExtracted(res); add('assistant', res.summary || 'Target scope extracted.', res);
    }catch(e){ add('assistant','Extraction failed: '+e.message); }
    finally{setBusy(false); await refresh?.();}
  };
  const command = async()=>{
    if(!text.trim()) return;
    setBusy(true); add('user', text);
    try{
      const res = await request('/agent/command',{method:'POST',body:JSON.stringify({
        transcript:text, selected_target_id:targetId || null, selected_scan_id:scanId || null,
        approve, source:'v6_command_center'
      })});
      add('assistant', res?.act?.message || res?.response || res?.message || 'Command completed.', res);
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
        name: extracted.program_name || domain, domain,
        scope: (extracted.in_scope_domains||[]).join('\n') || domain,
        out_of_scope: (extracted.out_of_scope||[]).join('\n'),
        notes: extracted.rules_summary || 'Imported from Hunter Brain.'
      })});
      setTargetId(res.id); add('assistant',`Target created: ${res.name || res.domain}`,res);
    }catch(e){ add('assistant','Create target failed: '+e.message); }
    finally{setBusy(false); await refresh?.();}
  };
  const startScan = async(mode='passive')=>{
    if(!targetId){ add('assistant','Select or create a target first.'); return; }
    setBusy(true);
    try{
      const config = {execution_mode:'remote',source:'v6_command_center',profile:extracted?.recommended_profile||'recon',skip_ai:false,skip_hunter:false};
      const res = await request('/scans/',{method:'POST',body:JSON.stringify({target_id:targetId,mode,config:JSON.stringify(config)})});
      setScanId(res.id); add('assistant',`${mode} scan started: ${res.id.slice(0,8)}`,res);
    }catch(e){ add('assistant','Start scan failed: '+e.message); }
    finally{setBusy(false); await refresh?.();}
  };

  return <Card title="Hunter Brain // AI Chat" className="chat-card" action={<div className="card-badges"><Pill>Gemini</Pill><Pill tone="green">Ready</Pill></div>}>
    <div className="chat-context">
      <select value={targetId} onChange={e=>setTargetId(e.target.value)}>
        <option value="">Select target</option>{targets.map(t=><option key={t.id} value={t.id}>{t.name||t.domain} — {t.domain}</option>)}
      </select>
      <select value={scanId} onChange={e=>setScanId(e.target.value)}>
        <option value="">Select scan</option>{scans.map(s=><option key={s.id} value={s.id}>{s.id.slice(0,8)} — {s.status}/{s.phase}</option>)}
      </select>
    </div>
    <div className="chat-log">
      {messages.map((m,i)=><div key={i} className={`msg ${m.role}`}>
        <div className="msg-meta"><b>{m.role}</b>{m.ts&&<span>{fmtDate(m.ts).slice(11)}</span>}</div>
        <p>{m.text}</p><DebugDetails value={m.obj}/>
      </div>)}
      <div ref={bottom}/>
    </div>
    {extracted && <div className="extract-box">
      <div className="extract-summary">
        <div><span>Program</span><b>{extracted.program_name || extracted.primary_domain || 'Extracted target'}</b></div>
        <div><span>Scope</span><b>{(extracted.in_scope_domains||[]).length} in / {(extracted.out_of_scope||[]).length} out</b></div>
        <div><span>Profile</span><b>{extracted.recommended_profile || 'recon'}</b></div>
        <div><span>Confidence</span><b>{Math.round((extracted.confidence||0.6)*100)}%</b></div>
      </div>
      <div className="chips">{(extracted.technologies||[]).slice(0,8).map(x=><Pill key={x}>{x}</Pill>)}</div>
      <div className="actions"><button onClick={createTarget}>Create Target</button><DebugDetails value={extracted}/></div>
    </div>}
    <textarea value={text} onChange={e=>setText(e.target.value)} placeholder="Paste a target page, ask for recon, or review findings..." />
    <div className="chat-actions">
      <button className="primary" onClick={command} disabled={busy}>Send</button>
      <button onClick={extract} disabled={busy}>Extract Target</button>
      <button onClick={()=>startScan('passive')} disabled={busy}>Run Passive Scan</button>
      <button className={approve?'approval active':'approval'} onClick={()=>setApprove(v=>!v)} disabled={busy}>{approve?'Active Action Approved':'Approve Active Action'}</button>
    </div>
  </Card>;
}

function RunnerPanel({runners, models}){
  const online=runners?.online||[]; const runner=online[0];
  return <Card title="Runner Status" className="runner-card" action={<Pill tone={online.length?'green':'red'}>{online.length?'Online':'Offline'}</Pill>}>
    <div className="runner-primary"><span className={`status-orb ${online.length?'online':'offline'}`}/><div><b>{runner?.name||'No runner connected'}</b><span>{runner?.hostname||'Waiting for authenticated bridge'}</span></div></div>
    <div className="runner-metrics"><div><span>Mode</span><b>{runners?.current_mode||'hybrid'}</b></div><div><span>Tools</span><b>{runner?.tool_count||Object.keys(runner?.tools||{}).length||0}</b></div><div><span>AI</span><b>{models?.provider||'gemini'}</b></div></div>
    {runner&&<p className="runner-seen">Last seen {fmtDate(runner.last_seen_at)}</p>}
    <DebugDetails value={{runner,models}} label="Show runner details"/>
  </Card>;
}

function TargetsPanel({targets}){return <Card title="Targets" action={<Pill>{targets.length}</Pill>}><div className="list">{targets.slice(0,6).map(t=><div className="row" key={t.id}><div><b>{t.name||t.domain}</b><span>{t.domain}</span></div><Pill>{(t.scope||'').split('\n').filter(Boolean).length||1} scope</Pill></div>)}{!targets.length&&<div className="empty">No targets yet. Extract one in Hunter Brain.</div>}</div></Card>}
function ScansPanel({scans}){return <Card title="Live Scans" action={<Pill tone="warn">{scans.length}</Pill>}><div className="list">{scans.slice(0,6).map(s=><div className="row" key={s.id}><div><b>{s.id.slice(0,8)}</b><span>{s.mode} · {s.phase} · {fmtDate(s.created_at)}</span></div><Pill tone={String(s.status).includes('done')?'green':String(s.status).includes('fail')?'red':'warn'}>{s.status}</Pill></div>)}{!scans.length&&<div className="empty">No scans running.</div>}</div></Card>}
function FindingsPanel({findings}){return <Card title="Findings" action={<Pill tone="red">{findings.length}</Pill>}><div className="list">{findings.slice(0,6).map(f=><div className="row finding" key={f.id}><div><b>{clip(f.title,72)}</b><span>{f.tool||'unknown'} · {fmtDate(f.created_at)}</span></div><Pill tone={['critical','high'].includes(String(f.severity).toLowerCase())?'red':String(f.severity).toLowerCase()==='medium'?'warn':'green'}>{f.severity}</Pill></div>)}{!findings.length&&<div className="empty">No findings yet.</div>}</div></Card>}

function ActivityFeed({live, upgrades}){
  const events=useMemo(()=>[...(live?.live_events||[]),...(live?.recent_scan_events||[]).map(e=>({type:e.level,payload:e,created_at:e.created_at}))].slice(-80).reverse(),[live]);
  const renderEvent=(e,i)=><div key={`${e.created_at||''}-${i}`} className="event"><span>{fmtDate(e.created_at)}</span><b>{e.type||e.level||'event'}</b><p title={e.payload?.message||e.message||''}>{clip(e.payload?.message||e.message||e.payload?.action||e.payload||e,170)}</p></div>;
  return <Card title="Live Activity Feed" action={<Pill tone="green">Latest 8</Pill>}>
    <div className="brain-steps"><span>Observe</span><span>Reason</span><span>Think</span><span>Act</span><span>Learn</span></div>
    <div className="event-feed">{events.slice(0,8).map(renderEvent)}{!events.length&&<div className="empty">Waiting for live activity…</div>}</div>
    {events.length>8&&<details className="older-events"><summary>Show {events.length-8} older events</summary><div className="event-feed older">{events.slice(8,24).map(renderEvent)}</div></details>}
    <DebugDetails value={upgrades} label="Show system details"/>
  </Card>;
}

function AdvancedModules({live}){
  const [active,setActive]=useState('knowledge');
  const [data,setData]=useState({skills:[],tasks:[],takeovers:[],browser:null,mobile:null,templates:[],evals:[],kg:null});
  const [findingId,setFindingId]=useState(''); const [debate,setDebate]=useState(null); const [report,setReport]=useState(null);
  const [template,setTemplate]=useState('Generic Markdown'); const [apk,setApk]=useState({filename:'app.apk',package_name:''});
  const refresh=async()=>{ const [skills,tasks,takeovers,browser,mobile,templates,evals,kg]=await Promise.all([
    request('/skills/').catch(()=>[]),request('/tasks/').catch(()=>[]),request('/takeovers/open').catch(()=>[]),
    request('/browser/capabilities').catch(()=>null),request('/mobile/capabilities').catch(()=>null),request('/reports/templates').catch(()=>[]),
    request('/evals/results').catch(()=>[]),request('/knowledge/stats').catch(()=>null),]); setData({skills,tasks,takeovers,browser,mobile,templates,evals,kg}); };
  useEffect(()=>{refresh();},[]);
  const runDebate=async()=>findingId&&setDebate(await request(`/debate/findings/${findingId}/run`,{method:'POST'}).catch(e=>({error:e.message})));
  const getRecords=async()=>findingId&&setDebate(await request(`/debate/records/${findingId}`).catch(e=>({error:e.message})));
  const genReport=async()=>findingId&&setReport(await request(`/reports/finding/${findingId}/draft?template=${encodeURIComponent(template)}`,{method:'POST'}).catch(e=>({error:e.message})));
  const runEvals=async()=>{await request('/evals/run-basic',{method:'POST'}).catch(()=>null);await refresh();};
  const saveApk=async()=>{await request('/mobile/apk/metadata',{method:'POST',body:JSON.stringify({...apk,permissions:[],exported_components:[],findings:[]})}).catch(()=>null);await refresh();};
  const tabs=[['knowledge','Knowledge Graph'],['skills','Skill Registry'],['agents','Agent Command Center'],['takeover','Takeover Monitor'],['debate','Debate Engine'],['browser','Browser DevTools MCP'],['mobile','Mobile APK Hunter'],['reports','Report Builder'],['evals','Evals / Revisions'],['programs','Program Radar / Earnings'],['terminal','Live Terminal']];
  const programs=live?.recent_programs||[]; const accounts=live?.bounty_accounts||[];
  const views={
    knowledge:<Card title="Knowledge Graph" action={<Pill tone="purple">Cross-scan memory</Pill>}><div className="advanced-stats"><Stat label="techniques" value={data.kg?.total_techniques??0}/><Stat label="chains" value={data.kg?.total_chains??0}/><Stat label="attempts" value={data.kg?.total_attempts??0}/><Stat label="success" value={data.kg?.overall_success_rate??0}/></div><div className="graph-placeholder"><div>Assets</div><span/><div>Techniques</div><span/><div>Evidence</div><span/><div>Reports</div></div><DebugDetails value={data.kg}/></Card>,
    skills:<Card title="Skill Registry" action={<Pill>{data.skills.length} skills</Pill>}><div className="list">{data.skills.slice(0,12).map(s=><div className="row" key={s.name}><div><b>{s.display_name}</b><span>{s.category} · {s.phase}</span></div><Pill tone={s.requires_approval?'warn':s.passive_safe?'green':'accent'}>{s.risk_level}</Pill></div>)}</div></Card>,
    agents:<Card title="Agent Command Center" action={<Pill>{data.tasks.length} tasks</Pill>}><div className="notice">Orchestration and task state only. Scan execution remains approval-gated.</div><div className="list">{data.tasks.slice(0,10).map(t=><div className="row" key={t.id}><div><b>{t.title}</b><span>{t.agent_name} · {t.progress}%</span></div><Pill tone={t.status==='completed'?'green':t.status==='failed'?'red':'warn'}>{t.status}</Pill></div>)}{!data.tasks.length&&<div className="empty">No agent tasks.</div>}</div></Card>,
    takeover:<Card title="Takeover Monitor" action={<Pill tone="warn">Scope guarded</Pill>}><div className="list">{data.takeovers.map(c=><div className="row" key={c.id}><div><b>{c.domain}</b><span>{c.service||'unknown'} · {c.cname||'no cname'}</span></div><Pill>{c.status}</Pill></div>)}{!data.takeovers.length&&<div className="empty">No open takeover candidates.</div>}</div></Card>,
    debate:<Card title="Debate Engine" action={<Pill tone="warn">Review only</Pill>}><div className="notice">Evidence is treated as untrusted and no tools run from this panel.</div><div className="inline-form"><input value={findingId} onChange={e=>setFindingId(e.target.value)} placeholder="Finding ID"/><button onClick={runDebate}>Run Debate</button><button onClick={getRecords}>Load Records</button></div>{debate&&<div className="result-summary"><b>{debate.verdict||debate.status||debate.error||'Debate complete'}</b><span>{clip(debate.summary||debate.reason||'',220)}</span></div>}<DebugDetails value={debate}/></Card>,
    browser:<Card title="Browser DevTools MCP" action={<Pill tone={data.browser?.enabled?'green':'warn'}>{data.browser?.enabled?'Enabled':'Disabled'}</Pill>}><div className="notice">Metadata and capabilities only; navigation is not initiated from this view.</div><div className="chips">{(data.browser?.capabilities||[]).map(c=><Pill key={c}>{c}</Pill>)}</div><DebugDetails value={data.browser}/></Card>,
    mobile:<Card title="Mobile APK Hunter" action={<Pill>Static analysis</Pill>}><div className="chips">{(data.mobile?.capabilities||[]).slice(0,10).map(c=><Pill key={c}>{c}</Pill>)}</div><div className="inline-form"><input value={apk.filename} onChange={e=>setApk({...apk,filename:e.target.value})} placeholder="app.apk"/><button onClick={saveApk}>Save APK Metadata</button></div><DebugDetails value={data.mobile}/></Card>,
    reports:<Card title="Report Builder" action={<Pill>Templates</Pill>}><div className="inline-form"><select value={template} onChange={e=>setTemplate(e.target.value)}>{(data.templates.length?data.templates:['Generic Markdown']).map(t=><option key={t}>{t}</option>)}</select><input value={findingId} onChange={e=>setFindingId(e.target.value)} placeholder="Finding ID"/><button onClick={genReport}>Draft Report</button></div>{report&&<div className="result-summary"><b>{report.title||report.status||report.error||'Draft created'}</b><span>{clip(report.summary||report.content||'',240)}</span></div>}<DebugDetails value={report}/></Card>,
    evals:<Card title="Evals / Revisions" action={<button className="small-button" onClick={runEvals}>Run Basic Evals</button>}><div className="list">{data.evals.slice(0,10).map(e=><div className="row" key={e.id}><div><b>{e.test_name}</b><span>{clip(e.details,100)}</span></div><Pill tone={e.status==='pass'?'green':e.status==='fail'?'red':'warn'}>{e.status}</Pill></div>)}{!data.evals.length&&<div className="empty">No evaluation results.</div>}</div></Card>,
    programs:<Card title="Program Radar / Earnings" action={<Pill tone="green">{programs.length} programs</Pill>}><div className="advanced-stats"><Stat label="programs" value={programs.length}/><Stat label="accounts" value={accounts.length}/><Stat label="month" value="$0" tone="green"/><Stat label="mode" value="learn"/></div><div className="list">{programs.slice(0,8).map(p=><div className="row" key={p.id}><div><b>{p.name}</b><span>{p.platform} · score {p.value_score}</span></div><Pill tone={p.offers_bounty?'green':'warn'}>{p.offers_bounty?'bounty':'vdp'}</Pill></div>)}{!programs.length&&<div className="empty">Sync accounts or run Program Radar.</div>}</div></Card>,
    terminal:<Card title="Live Terminal" action={<Pill tone="green">Ready</Pill>}><div className="terminal"><p><span>$</span> hunter brain ready</p><p><span>$</span> select target → recon → review findings</p><p><span>$</span> active actions require explicit approval</p><p><span>$</span> runner bridge waiting for structured argv jobs</p></div></Card>,
  };
  return <section className="advanced-shell"><div className="section-title"><div><span>Advanced Workspace</span><h2>Specialist modules, one view at a time</h2></div><Pill tone="purple">All features available</Pill></div><div className="module-tabs" role="tablist">{tabs.map(([id,label])=><button key={id} className={active===id?'active':''} onClick={()=>setActive(id)} role="tab" aria-selected={active===id}>{label}</button>)}</div><div className="module-view">{views[active]}</div></section>;
}

export default function App(){
  const {live,targets,scans,findings,runners,models,upgrades,err,refresh}=useDashboardData();
  const recentScans=live?.recent_scans||scans||[]; const recentFindings=live?.recent_findings||findings||[];
  const severity=useMemo(()=>recentFindings.reduce((a,f)=>{const s=String(f.severity||'info').toLowerCase();a[s]=(a[s]||0)+1;return a;},{}),[recentFindings]);
  const online=(runners?.online||[]).length;
  return <div className="app-shell"><div className="grid-bg"/>
    <header className="topbar"><div className="brand"><div className="brand-mark">B6</div><div><h1>BOUNTYOS v6</h1><p>Personal bug bounty command center</p></div></div><div className="top-pills"><Pill tone="green">AI · {models?.provider||'Gemini'}</Pill><Pill tone={online?'green':'red'}>Runner · {online?'Online':'Offline'}</Pill><Pill tone={err?'warn':'accent'}>API · {err?'Warning':'Live'}</Pill></div></header>
    <main className="layout">
      <section className="hero"><HunterChat targets={targets||[]} scans={recentScans} refresh={refresh}/><div className="hero-side"><RunnerPanel runners={runners} models={models}/><div className="metrics"><Stat label="targets" value={(targets||[]).length}/><Stat label="scans" value={recentScans.length}/><Stat label="findings" value={recentFindings.length}/><Stat label="critical / high" value={(severity.critical||0)+(severity.high||0)} tone="bad"/></div></div></section>
      <section className="overview-grid"><TargetsPanel targets={targets||[]}/><ScansPanel scans={recentScans}/><FindingsPanel findings={recentFindings}/></section>
      <ActivityFeed live={live} upgrades={upgrades}/>
      <AdvancedModules live={live}/>
    </main>
  </div>;
}
