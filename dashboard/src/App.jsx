import React, {useEffect, useMemo, useRef, useState} from 'react';

const API = '/api/v1';
const emptyMessage = {summary: '', actions: [], logs: [], raw: null, evidence: [], scan_id: null, target_id: null, planner: null, events: []};

async function api(path, options = {}) {
  const res = await fetch(API + path, {headers: {'Content-Type': 'application/json', ...(options.headers || {})}, ...options});
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = {text}; }
  if (!res.ok) {
    const err = new Error(data?.detail || data?.message || data?.error || `${res.status} ${res.statusText}`);
    err.status = res.status;
    err.payload = data;
    throw err;
  }
  return data;
}

const shortId = value => value ? String(value).slice(0, 8) : '—';
const asList = value => Array.isArray(value) ? value : value ? [value] : [];
const truncate = (value, max = 220) => {
  const text = typeof value === 'string' ? value : JSON.stringify(value ?? '');
  return text.length > max ? `${text.slice(0, max).trim()}…` : text;
};

function parseJsonText(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  const unwrapped = trimmed.startsWith('```') ? trimmed.replace(/^```(?:json)?/i, '').replace(/```$/i, '').trim() : trimmed;
  if (!unwrapped.startsWith('{') && !unwrapped.startsWith('[')) return null;
  try { return JSON.parse(unwrapped); } catch { return null; }
}

function listText(items) {
  return asList(items).map(item => {
    if (typeof item === 'string') return item;
    return item?.next_safe_action || item?.label || item?.name || item?.tool || JSON.stringify(item);
  }).filter(Boolean);
}

function cleanSummary(text, raw) {
  const parsed = parseJsonText(text);
  const payload = parsed || raw?.act?.structured || raw?.structured || null;
  if (!payload) return text || 'Command completed.';

  const guidance = payload.operational_guidance || payload.guidance || payload;
  const actions = listText(guidance.next_safe_actions || guidance.next_actions || guidance);
  const tools = listText(guidance.selected_tools || guidance.tools);
  const confidence = guidance.confidence ? `Confidence: ${guidance.confidence}.` : '';
  const impact = guidance.impact ? `Impact: ${guidance.impact}.` : '';

  const lines = [];
  if (actions.length) lines.push(`Recommended next steps: ${actions.slice(0, 4).join(', ')}.`);
  if (tools.length) lines.push(`Tools selected: ${tools.slice(0, 6).join(', ')}.`);
  if (confidence || impact) lines.push([confidence, impact].filter(Boolean).join(' '));
  return lines.join('\n') || 'I reviewed the current context and prepared the next safe steps.';
}

function extractActions(data) {
  const act = data?.act || data || {};
  const parsed = parseJsonText(act.response || act.message || data?.summary || data?.message || data?.response || '');
  const guidance = parsed?.operational_guidance || parsed?.guidance || parsed;
  return listText(act.next_actions || data?.next_actions || act.actions || data?.actions || guidance?.next_safe_actions || guidance?.next_actions).slice(0, 6);
}

function normalizeResponse(data, fallbackSummary = 'Done.') {
  const act = data?.act || data || {};
  const rawSummary = act.response || act.message || data?.summary || data?.message || data?.response || fallbackSummary;
  const scanId = act.scan_id || data?.scan_id || data?.reason?.scan_id || null;
  const targetId = act.target_id || data?.target_id || data?.reason?.target_id || null;
  const findings = asList(act.findings || data?.findings);
  const rawLogs = asList(act.logs || data?.logs || act.output || data?.output);
  const events = asList(act.events || data?.events || data?.scan_events);
  return {
    ...emptyMessage,
    summary: cleanSummary(rawSummary, data),
    actions: extractActions(data),
    logs: rawLogs.map(item => typeof item === 'string' ? item : JSON.stringify(item, null, 2)),
    evidence: asList(act.evidence || data?.evidence || findings),
    planner: data?.think || act.planner || data?.planner || null,
    raw: data,
    scan_id: scanId,
    target_id: targetId,
    events,
  };
}

function Badge({children, tone = 'neutral'}) { return <span className={`badge ${tone}`}>{children}</span>; }
function PillButton({children, ...props}) { return <button className="pill-button" {...props}>{children}</button>; }

function Expanders({message}) {
  const groups = [
    ['Execution logs', message.logs],
    ['Raw JSON', message.raw],
    ['Planner details', message.planner],
    ['Scan events', message.events],
    ['Evidence', message.evidence],
  ];
  return <div className="expanders">
    {groups.map(([label, value]) => {
      const hasValue = Array.isArray(value) ? value.length > 0 : Boolean(value);
      if (!hasValue) return null;
      return <details key={label}>
        <summary>{label}</summary>
        <pre>{typeof value === 'string' ? value : JSON.stringify(value, null, 2)}</pre>
      </details>;
    })}
  </div>;
}

function ChatMessage({message}) {
  return <article className={`message ${message.role}`}>
    <div className="message-meta">
      <span>{message.role === 'user' ? 'You' : message.role === 'system' ? 'System' : 'Hunter Brain'}</span>
      {message.model && <Badge>{message.model}</Badge>}
    </div>
    <div className="message-body">{message.summary}</div>
    {message.actions?.length > 0 && <div className="action-strip">{message.actions.map((a, i) => <Badge key={i} tone="cyan">{String(a)}</Badge>)}</div>}
    {message.scan_id && <div className="task-chip">Scan <b>{shortId(message.scan_id)}</b></div>}
    <Expanders message={message}/>
  </article>;
}

function StatusCard({title, children, action}) {
  return <section className="status-card"><div className="status-title"><h3>{title}</h3>{action}</div>{children}</section>;
}

function useOpsData() {
  const [data, setData] = useState({targets: [], scans: [], findings: [], live: null, runners: null, models: null, browserStatus: null, caidoStatus: null});
  const [error, setError] = useState('');
  const refresh = async () => {
    const [targets, scans, findings, live, runners, models, browserStatus, caidoStatus] = await Promise.all([
      api('/targets/').catch(() => []), api('/scans/').catch(() => []), api('/findings/').catch(() => []),
      api('/live/snapshot').catch(() => null), api('/runners/capabilities').catch(() => null), api('/ai/models').catch(() => null),
      api('/integrations/browser/status').catch(() => null), api('/integrations/caido/status').catch(() => null),
    ]);
    setData({targets, scans, findings, live, runners, models, browserStatus, caidoStatus});
    setError('');
  };
  useEffect(() => { refresh().catch(e => setError(e.message)); const id = setInterval(() => refresh().catch(e => setError(e.message)), 4500); return () => clearInterval(id); }, []);
  return {...data, error, refresh};
}

function Sidebar({data, selectedTargetId, selectedScanId, onSelectTarget, onSelectScan, onRefresh}) {
  const online = data.runners?.online || [];
  const runner = online[0];
  const selectedTarget = data.targets.find(t => t.id === selectedTargetId) || data.targets[0];
  const selectedScan = data.scans.find(s => s.id === selectedScanId) || data.scans[0];
  const tools = runner?.tool_count || Object.keys(runner?.tools || {}).length || 0;
  return <aside className="right-rail">
    <StatusCard title="System" action={<PillButton onClick={onRefresh}>Refresh</PillButton>}>
      <div className="signal-row"><span className={`signal ${online.length ? 'on' : 'off'}`}/><div><b>{online.length ? 'Runner online' : 'Runner offline'}</b><small>{runner?.name || 'Start local runner'}</small></div></div>
      <div className="mini-stats"><div><b>{tools}</b><span>tools</span></div><div><b>{data.models?.provider || 'gemini'}</b><span>AI</span></div><div><b>{data.models?.chat_model || 'flash-lite'}</b><span>chat</span></div></div>
    </StatusCard>
    <StatusCard title="Active Target">
      <select value={selectedTargetId} onChange={e => onSelectTarget(e.target.value)}><option value="">No target selected</option>{data.targets.map(t => <option key={t.id} value={t.id}>{t.name || t.domain}</option>)}</select>
      <div className="compact-copy"><b>{selectedTarget?.domain || 'No target yet'}</b><span>{truncate(selectedTarget?.scope || 'Create or select a target to run recon.', 140)}</span></div>
    </StatusCard>
    <StatusCard title="Scan Status">
      <select value={selectedScanId} onChange={e => onSelectScan(e.target.value)}><option value="">No scan selected</option>{data.scans.map(s => <option key={s.id} value={s.id}>{shortId(s.id)} · {s.status}</option>)}</select>
      <div className="compact-copy"><b>{selectedScan ? `${selectedScan.mode || 'scan'} · ${selectedScan.status}` : 'Idle'}</b><span>{selectedScan ? `Phase ${selectedScan.phase || 'queued'} · ${shortId(selectedScan.id)}` : 'Start work from Hunter Brain.'}</span></div>
    </StatusCard>
  </aside>;
}

function LogsDrawer({open, live}) {
  const events = useMemo(() => {
    const liveEvents = asList(live?.live_events).map(e => ({kind: e.type || 'live', message: e.message || e.payload?.message || e.payload || e}));
    const scanEvents = asList(live?.recent_scan_events).map(e => ({kind: e.level || e.tool || 'scan', message: e.message}));
    return [...liveEvents, ...scanEvents].slice(-60).reverse();
  }, [live]);
  return <section className={`logs-drawer ${open ? 'open' : ''}`}>
    <div className="drawer-handle"><span>Live logs</span><Badge>{events.length}</Badge></div>
    <div className="log-list">{events.map((event, i) => <div className="log-row" key={i}><span>{event.kind}</span><p>{truncate(event.message, 180)}</p></div>)}{!events.length && <p className="muted">No live logs yet.</p>}</div>
  </section>;
}

function FindingsPage({data}) {
  return <section className="page-card"><h2>Findings</h2><p className="muted">Parsed findings stay here. Chat stays clean.</p><div className="finding-grid">
    {data.findings.map(f => <div className="finding-card big" key={f.id}><Badge tone={String(f.severity).toLowerCase()}>{f.severity || 'info'}</Badge><b>{f.title}</b><small>{f.tool || 'unknown tool'} · {f.url || 'no URL'}</small><p>{truncate(f.description || f.evidence || 'No detail yet.', 260)}</p></div>)}
    {!data.findings.length && <p className="muted">No parsed findings yet.</p>}
  </div></section>;
}

function ToolsPage({data}) {
  const runner = data.runners?.online?.[0];
  const tools = Object.entries(runner?.tools || {});
  return <section className="page-card"><h2>Tools</h2><p className="muted">Runner inventory. Broken tools should be fixed in install scripts, not hidden in chat.</p><div className="tool-grid">
    {tools.map(([name, meta]) => <div className="tool-card" key={name}><b>{name}</b><small>{meta.path || meta.binary}</small><p>{truncate(meta.version || 'version unknown', 110)}</p></div>)}
    {!tools.length && <p className="muted">Runner is offline or no tools reported.</p>}
  </div></section>;
}

function IntegrationsPage({data}) {
  const [forms, setForms] = useState({gemini: '', caidoUrl: '', caidoToken: '', browserUrl: '', burpUrl: '', zapUrl: '', hackeroneToken: '', bugcrowdToken: ''});
  const update = key => e => setForms(prev => ({...prev, [key]: e.target.value}));
  return <section className="page-card"><h2>Integrations</h2><p className="muted">Connectors live here, not inside Hunter Brain chat. Values are shown as setup fields; save buttons are placeholders until encrypted settings storage is added.</p>
    <div className="integration-grid">
      <StatusCard title="AI Models"><div className="compact-copy"><b>{data.models?.provider || 'gemini'}</b><span>Chat {data.models?.chat_model || 'gemini-2.5-flash-lite'} · Agentic {data.models?.agentic_model || 'gemini-3.5-flash'}</span></div><input placeholder="GEMINI_API_KEY" value={forms.gemini} onChange={update('gemini')} /></StatusCard>
      <StatusCard title="Chrome DevTools MCP"><div className="compact-copy"><b>{data.browserStatus?.enabled ? 'Configured' : 'Not configured'}</b><span>{data.browserStatus?.url || 'Set CHROME_DEVTOOLS_MCP_URL'}</span></div><input placeholder="http://localhost:PORT" value={forms.browserUrl} onChange={update('browserUrl')} /></StatusCard>
      <StatusCard title="Caido"><div className="compact-copy"><b>{data.caidoStatus?.token_set ? 'Token configured' : 'Missing token'}</b><span>{data.caidoStatus?.url || 'Set CAIDO_URL and CAIDO_API_TOKEN'}</span></div><input placeholder="CAIDO_URL" value={forms.caidoUrl} onChange={update('caidoUrl')} /><input placeholder="CAIDO_API_TOKEN" value={forms.caidoToken} onChange={update('caidoToken')} /></StatusCard>
      <StatusCard title="Burp Suite"><input placeholder="BURP_URL" value={forms.burpUrl} onChange={update('burpUrl')} /><input placeholder="BURP_APIKEY" /></StatusCard>
      <StatusCard title="OWASP ZAP"><input placeholder="ZAP_URL" value={forms.zapUrl} onChange={update('zapUrl')} /><input placeholder="ZAP_APIKEY" /></StatusCard>
      <StatusCard title="Bug bounty platforms"><input placeholder="HackerOne API token" value={forms.hackeroneToken} onChange={update('hackeroneToken')} /><input placeholder="Bugcrowd token" value={forms.bugcrowdToken} onChange={update('bugcrowdToken')} /></StatusCard>
    </div>
  </section>;
}

function SettingsPage() {
  return <section className="page-card"><h2>Settings</h2><p className="muted">BountyOS is personal-use only right now. Keep active validation approval-gated and stay inside authorized program scope.</p><div className="settings-list"><div><b>Safety</b><span>Active checks require approval.</span></div><div><b>Logs</b><span>Raw JSON and stdout stay collapsed until you open them.</span></div><div><b>Layout</b><span>One clean command page, separate pages for tools/integrations/findings.</span></div></div></section>;
}

export default function App() {
  const data = useOpsData();
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [showLogs, setShowLogs] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [selectedScanId, setSelectedScanId] = useState('');
  const [view, setView] = useState('chat');
  const chatRef = useRef(null);
  const [messages, setMessages] = useState([{...emptyMessage, role: 'system', summary: 'Hunter Brain ready. Main chat stays clean; open Logs or Raw JSON only when needed.'}]);

  useEffect(() => { chatRef.current?.scrollTo({top: chatRef.current.scrollHeight, behavior: 'smooth'}); }, [messages]);
  const push = message => setMessages(prev => [...prev, {ts: new Date().toISOString(), ...message}].slice(-40));
  const runAction = async (label, fn) => { setBusy(true); try { await fn(); } catch (e) { push({...emptyMessage, role: 'assistant', summary: `${label} failed: ${e.message}`, raw: e.payload || {error: e.message, status: e.status}}); } finally { setBusy(false); data.refresh().catch(() => {}); } };

  const send = () => runAction('Send', async () => {
    if (!text.trim()) return push({...emptyMessage, role: 'assistant', summary: 'Type a message first.'});
    const transcript = text; push({...emptyMessage, role: 'user', summary: transcript}); setText('');
    const res = await api('/agent/command', {method: 'POST', body: JSON.stringify({transcript, selected_target_id: selectedTargetId || null, selected_scan_id: selectedScanId || null, source: 'dashboard'})});
    const normalized = normalizeResponse(res, 'Command completed.');
    if (normalized.target_id) setSelectedTargetId(normalized.target_id); if (normalized.scan_id) setSelectedScanId(normalized.scan_id);
    push({role: 'assistant', model: normalized.raw?.act?.model_used || normalized.raw?.act?.model, ...normalized});
  });

  const createTarget = () => runAction('Create target', async () => {
    const domain = text.trim().split(/\s+/)[0]?.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!domain) return push({...emptyMessage, role: 'assistant', summary: 'Paste a domain or URL first.'});
    const res = await api('/targets/', {method: 'POST', body: JSON.stringify({name: domain, domain, scope: domain, notes: 'Created from Hunter Brain console'})});
    setSelectedTargetId(res.id); push({role: 'assistant', ...normalizeResponse(res, `Target created: ${res.domain || domain}`), target_id: res.id});
  });

  const passiveRecon = () => runAction('Run passive recon', async () => {
    if (!selectedTargetId) return push({...emptyMessage, role: 'assistant', summary: 'Select or create a target before starting passive recon.'});
    const res = await api('/scans/', {method: 'POST', body: JSON.stringify({target_id: selectedTargetId, mode: 'passive', config: JSON.stringify({source: 'hunter_brain_console', execution_mode: 'hybrid'})})});
    setSelectedScanId(res.id); push({role: 'assistant', ...normalizeResponse(res, `Passive recon queued. Open Logs to watch raw execution.`), scan_id: res.id, target_id: selectedTargetId});
  });

  const approveActive = () => runAction('Approve active scan', async () => {
    if (!selectedTargetId) return push({...emptyMessage, role: 'assistant', summary: 'Select a target before approving active work.'});
    const transcript = text.trim() || 'Run approved active scan for the selected target';
    const res = await api('/agent/command', {method: 'POST', body: JSON.stringify({transcript, selected_target_id: selectedTargetId, selected_scan_id: selectedScanId || null, approve: true, source: 'dashboard'})});
    const normalized = normalizeResponse(res, 'Approved action submitted.'); if (normalized.scan_id) setSelectedScanId(normalized.scan_id); push({role: 'assistant', ...normalized});
  });

  const pages = {chat: 'Hunter Brain', findings: 'Findings', integrations: 'Integrations', tools: 'Tools', settings: 'Settings'};
  return <div className="ops-shell">
    <main className="chat-panel">
      <header className="topbar"><div><p className="eyebrow">BountyOS v6</p><h1>{pages[view]}</h1></div><nav className="topbar-badges">{Object.entries(pages).map(([key, label]) => <button key={key} className={view === key ? 'nav-button active' : 'nav-button'} onClick={() => setView(key)}>{label}</button>)}<Badge tone={(data.runners?.online || []).length ? 'green' : 'red'}>{(data.runners?.online || []).length ? 'runner online' : 'runner offline'}</Badge><Badge tone="cyan">{data.models?.chat_model || 'gemini'}</Badge></nav></header>

      {view === 'chat' && <><section className="chat-stream" ref={chatRef}>{messages.map((message, index) => <ChatMessage key={index} message={message}/>)}</section><section className="composer"><textarea value={text} onChange={e => setText(e.target.value)} placeholder="Ask Hunter Brain, paste target page, or request recon..." onKeyDown={e => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) send(); }}/><div className="composer-actions"><button className="primary" onClick={send} disabled={busy}>Send</button><button onClick={passiveRecon} disabled={busy}>Run Passive Recon</button><button onClick={createTarget} disabled={busy}>Create Target</button><button onClick={approveActive} disabled={busy}>Approve Active</button><button onClick={() => setShowLogs(v => !v)}>{showLogs ? 'Hide Logs' : 'Show Logs'}</button></div></section><LogsDrawer open={showLogs} live={data.live}/></>}
      {view === 'findings' && <FindingsPage data={data}/>} {view === 'integrations' && <IntegrationsPage data={data}/>} {view === 'tools' && <ToolsPage data={data}/>} {view === 'settings' && <SettingsPage/>}
    </main>
    <Sidebar data={data} selectedTargetId={selectedTargetId} selectedScanId={selectedScanId} onSelectTarget={setSelectedTargetId} onSelectScan={setSelectedScanId} onRefresh={data.refresh}/>
  </div>;
}
