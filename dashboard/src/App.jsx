import React, {useEffect, useMemo, useState} from 'react';

const API = '/api/v1';
const NAV = ['Dashboard','Hunter Brain','Targets','Scans','Findings','Runners','Knowledge Graph','Reports','Settings'];

async function api(path, options={}){
  const res = await fetch(API + path, {headers:{'Content-Type':'application/json', ...(options.headers||{})}, ...options});
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = {raw:text}; }
  if(!res.ok){
    const detail = data?.detail || data?.message || data?.error || `${res.status} ${res.statusText}`;
    const err = new Error(detail); err.status = res.status; throw err;
  }
  return data;
}
const trim = (v,n=120)=>String(v||'').length>n ? String(v).slice(0,n).trim()+'…' : String(v||'');
const when = v => v ? String(v).replace('T',' ').slice(0,19) : '—';

function Badge({children,tone='cyan'}){ return <span className={`badge ${tone}`}>{children}</span>; }
function Card({title, action, children, className=''}){ return <section className={`card ${className}`}><div className="card-title"><h2>{title}</h2>{action}</div>{children}</section>; }
function Stat({label,value,tone='cyan'}){ return <div className="stat"><strong className={tone}>{value}</strong><span>{label}</span></div>; }
function Empty({children}){ return <div className="empty">{children}</div>; }
function Details({value}){ return value ? <details className="details"><summary>Show details</summary><pre>{JSON.stringify(value,null,2)}</pre></details> : null; }

function useData(){
  const [data,setData] = useState({targets:[],scans:[],findings:[],live:null,runners:null,models:null,upgrades:null});
  const [error,setError] = useState('');
  const refresh = async()=>{
    try{
      const [targets,scans,findings,live,runners,models,upgrades] = await Promise.all([
        api('/targets/').catch(()=>[]), api('/scans/').catch(()=>[]), api('/findings/').catch(()=>[]),
        api('/live/snapshot').catch(()=>null), api('/runners/capabilities').catch(()=>null),
        api('/ai/models').catch(()=>null), api('/upgrades/').catch(()=>null),
      ]);
      setData({targets,scans,findings,live,runners,models,upgrades}); setError('');
    }catch(e){ setError(e.message); }
  };
  useEffect(()=>{ refresh(); const id=setInterval(refresh,5000); return()=>clearInterval(id); },[]);
  return {...data,error,refresh};
}

function HunterBrain({targets, scans, refresh}){
  const [text,setText] = useState('');
  const [targetId,setTargetId] = useState('');
  const [scanId,setScanId] = useState('');
  const [busy,setBusy] = useState(false);
  const [notice,setNotice] = useState('Ready. Paste a scope page or ask for recon.');
  const [messages,setMessages] = useState([{role:'system', text:'Hunter Brain ready for Gemini-powered recon workflow.'}]);
  const [extracted,setExtracted] = useState(null);
  const selectedTarget = targets.find(t=>t.id===targetId);
  const add = (role, msg, details=null)=>setMessages(m=>[...m,{role,text:msg,details,ts:new Date().toISOString()}].slice(-24));
  const run = async(label, fn)=>{ setBusy(true); setNotice(`${label}...`); try{ await fn(); } finally{ setBusy(false); await refresh?.(); } };
  const send = ()=>run('Sending command', async()=>{
    if(!text.trim()) return setNotice('Type a command first.');
    add('user', text);
    try{
      const res = await api('/agent/command',{method:'POST',body:JSON.stringify({transcript:text,selected_target_id:targetId||null,selected_scan_id:scanId||null,source:'dashboard'})});
      add('assistant', res?.act?.message || res?.response || res?.message || 'Command completed.', res); setNotice('Command completed.');
    }catch(e){ add('assistant', e.status===404?'Backend endpoint not available':`Command failed: ${e.message}`); setNotice(e.status===404?'Backend endpoint not available':e.message); }
  });
  const extract = ()=>run('Extracting target', async()=>{
    if(!text.trim()) return setNotice('Paste target/scope text first.');
    add('user', text);
    try{
      const res = await api('/ai/extract-target-page',{method:'POST',body:JSON.stringify({text})});
      setExtracted(res); add('assistant', res.summary || 'Target extracted.', res); setNotice('Target extraction complete.');
    }catch(e){ const msg=e.status===404?'Backend endpoint not available':'Extraction failed: '+e.message; add('assistant', msg); setNotice(msg); }
  });
  const createTarget = ()=>run('Creating target', async()=>{
    const domain = (extracted?.in_scope_domains||[])[0] || extracted?.primary_domain || text.trim().split(/\s+/)[0];
    if(!domain) return setNotice('No domain found. Paste a domain or extract a target first.');
    try{
      const res = await api('/targets/',{method:'POST',body:JSON.stringify({name:extracted?.program_name||domain,domain,scope:(extracted?.in_scope_domains||[]).join('\n')||domain,out_of_scope:(extracted?.out_of_scope||[]).join('\n'),notes:extracted?.rules_summary||'Created from dashboard'})});
      setTargetId(res.id); add('assistant',`Target created: ${res.domain}`,res); setNotice('Target created.');
    }catch(e){ const msg=e.status===404?'Backend endpoint not available':'Create target failed: '+e.message; add('assistant', msg); setNotice(msg); }
  });
  const passiveScan = ()=>run('Starting passive scan', async()=>{
    if(!targetId) return setNotice('Select or create a target first.');
    try{
      const config = JSON.stringify({execution_mode:'hybrid',source:'v6_dashboard',profile:'passive'});
      const res = await api('/scans/',{method:'POST',body:JSON.stringify({target_id:targetId,mode:'passive',config})});
      setScanId(res.id); add('assistant',`Passive scan started: ${res.id.slice(0,8)}`,res); setNotice('Passive scan started.');
    }catch(e){ const msg=e.status===404?'Backend endpoint not available':'Start scan failed: '+e.message; add('assistant', msg); setNotice(msg); }
  });
  return <Card title="Hunter Brain" className="hunter" action={<Badge tone={busy?'amber':'green'}>{busy?'Working':'Ready'}</Badge>}>
    <div className="notice">{notice}</div>
    <div className="context-row"><select value={targetId} onChange={e=>setTargetId(e.target.value)}><option value="">Select target</option>{targets.map(t=><option key={t.id} value={t.id}>{t.name||t.domain}</option>)}</select><select value={scanId} onChange={e=>setScanId(e.target.value)}><option value="">Select scan</option>{scans.map(s=><option key={s.id} value={s.id}>{s.id.slice(0,8)} · {s.status}</option>)}</select></div>
    {selectedTarget&&<div className="selected-target"><b>{selectedTarget.domain}</b><span>{trim(selectedTarget.scope,160)}</span></div>}
    <div className="chat-window">{messages.map((m,i)=><div key={i} className={`chat-msg ${m.role}`}><b>{m.role}</b><p>{m.text}</p><Details value={m.details}/></div>)}</div>
    <textarea value={text} onChange={e=>setText(e.target.value)} placeholder="Paste a target page, ask for recon, or review findings..." />
    <div className="button-row"><button className="primary" onClick={send} disabled={busy}>Send</button><button onClick={extract} disabled={busy}>Extract Target</button><button onClick={passiveScan} disabled={busy}>Run Passive Scan</button><button onClick={createTarget} disabled={busy}>Create Target</button></div>
  </Card>;
}

function Activity({live}){
  const events = [...(live?.live_events||[]), ...(live?.recent_scan_events||[]).map(e=>({type:e.level,message:e.message,created_at:e.created_at}))].slice(-8).reverse();
  return <Card title="Recent Activity" action={<Badge>{events.length} latest</Badge>}><div className="activity-list">{events.map((e,i)=><div className="activity" key={i}><span>{when(e.created_at)}</span><b>{e.type||'event'}</b><p>{trim(e.message||e.payload?.message||e.payload||e,150)}</p></div>)}{!events.length&&<Empty>No live activity yet.</Empty>}</div></Card>;
}
function RunnerCard({runners,onRefresh}){ const online=runners?.online||[]; const first=online[0]; return <Card title="Runner Status" action={<button className="mini" onClick={onRefresh}>Refresh Runner</button>}><div className="status-line"><span className={`dot ${online.length?'on':'off'}`}/><div><b>{online.length?'Runner online':'No runner online'}</b><p>{first?.name||'Start scripts/start-local-runner.sh'}</p></div></div><div className="mini-grid"><Stat label="online" value={online.length} tone={online.length?'green':'red'}/><Stat label="mode" value={runners?.current_mode||'hybrid'}/><Stat label="tools" value={first?.tool_count||Object.keys(first?.tools||{}).length||0}/></div></Card>; }
function ModelCard({models}){ return <Card title="AI Model"><div className="model-lines"><p><span>Provider</span><b>{models?.provider||'gemini'}</b></p><p><span>Main</span><b>{models?.main_model||'gemini-2.5-pro'}</b></p><p><span>Recon</span><b>{models?.recon_model||'gemini-2.5-flash'}</b></p><p><span>Vertex</span><b>{models?.vertex?'enabled':'off'}</b></p></div></Card>; }
function ListCard({title,items,type}){ return <Card title={title} action={<Badge>{items.length}</Badge>}><div className="list">{items.slice(0,8).map(item=><div className="list-row" key={item.id}><b>{type==='target'?(item.name||item.domain):type==='scan'?item.id.slice(0,8):trim(item.title,70)}</b><span>{type==='target'?item.domain:type==='scan'?`${item.mode} · ${item.status}`:`${item.severity} · ${item.tool||'unknown'}`}</span></div>)}{!items.length&&<Empty>No {title.toLowerCase()} yet.</Empty>}</div></Card>; }

function Page({active,data,refresh}){
  const {targets,scans,findings,live,runners,models,upgrades}=data;
  if(active==='Hunter Brain') return <HunterBrain targets={targets} scans={scans} refresh={refresh}/>;
  if(active==='Targets') return <ListCard title="Targets" items={targets} type="target"/>;
  if(active==='Scans') return <ListCard title="Scans" items={scans} type="scan"/>;
  if(active==='Findings') return <ListCard title="Findings" items={findings} type="finding"/>;
  if(active==='Runners') return <RunnerCard runners={runners} onRefresh={refresh}/>;
  if(active==='Knowledge Graph') return <Card title="Knowledge Graph"><p className="plain">Knowledge graph is available through backend modules and appears as scan intelligence is collected.</p><Details value={upgrades?.modules}/></Card>;
  if(active==='Reports') return <Card title="Reports"><p className="plain">Report builder stays connected to findings and quality agents. Select findings from the Findings page before drafting.</p></Card>;
  if(active==='Settings') return <Card title="Settings"><div className="settings"><Details value={models}/><Details value={upgrades}/></div></Card>;
  return <>
    <div className="top-grid"><RunnerCard runners={runners} onRefresh={refresh}/><ModelCard models={models}/><div className="stats-grid"><Stat label="targets" value={targets.length}/><Stat label="scans" value={scans.length}/><Stat label="findings" value={findings.length}/><Stat label="critical/high" value={findings.filter(f=>['critical','high'].includes(String(f.severity).toLowerCase())).length} tone="red"/></div></div>
    <div className="main-grid"><HunterBrain targets={targets} scans={scans} refresh={refresh}/><Activity live={live}/></div>
  </>;
}

export default function App(){
  const [active,setActive] = useState('Dashboard');
  const data = useData();
  return <div className="shell"><aside className="sidebar"><div className="logo"><span>B6</span><div><b>BountyOS v6</b><small>Personal command center</small></div></div><nav>{NAV.map(n=><button key={n} className={active===n?'active':''} onClick={()=>setActive(n)}>{n}</button>)}</nav></aside><main className="content"><header className="header"><div><p>Workspace</p><h1>{active}</h1></div><div className="header-badges"><Badge tone="green">Gemini/Vertex</Badge><Badge tone={(data.runners?.online||[]).length?'green':'red'}>{(data.runners?.online||[]).length?'Runner online':'Runner offline'}</Badge><Badge tone={data.error?'amber':'cyan'}>{data.error?'API warning':'API live'}</Badge></div></header>{data.error&&<div className="banner">{data.error}</div>}<Page active={active} data={data} refresh={data.refresh}/></main></div>;
}
