import React, {useEffect, useMemo, useState} from 'react';

const API = '/api/v1';
const emptyMessage = {
  summary: '',
  actions: [],
  logs: [],
  raw: null,
  evidence: [],
  scan_id: null,
  target_id: null,
  planner: null,
  events: [],
};

async function api(path, options = {}) {
  const res = await fetch(API + path, {
    headers: {'Content-Type': 'application/json', ...(options.headers || {})},
    ...options,
  });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = {text}; }
  if (!res.ok) {
    const message = data?.detail || data?.message || data?.error || `${res.status} ${res.statusText}`;
    const err = new Error(message);
    err.status = res.status;
    err.payload = data;
    throw err;
  }
  return data;
}

const shortId = value => value ? String(value).slice(0, 8) : '—';
const truncate = (value, max = 220) => {
  const text = typeof value === 'string' ? value : JSON.stringify(value ?? '');
  return text.length > max ? `${text.slice(0, max).trim()}…` : text;
};
const asList = value => Array.isArray(value) ? value : value ? [value] : [];

function normalizeResponse(data, fallbackSummary = 'Done.') {
  const act = data?.act || data || {};
  const scanId = act.scan_id || data?.scan_id || data?.reason?.scan_id || null;
  const targetId = act.target_id || data?.target_id || data?.reason?.target_id || null;
  const findings = asList(act.findings || data?.findings);
  const rawLogs = asList(act.logs || data?.logs || act.output || data?.output);
  const events = asList(act.events || data?.events || data?.scan_events);
  return {
    ...emptyMessage,
    summary: act.response || act.message || data?.summary || data?.message || data?.response || fallbackSummary,
    actions: asList(act.next_actions || data?.next_actions || act.actions || data?.actions),
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
    ['Show execution logs', message.logs],
    ['Show raw JSON', message.raw],
    ['Show planner details', message.planner],
    ['Show scan events', message.events],
    ['Show evidence', message.evidence],
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
    {message.actions?.length > 0 && <div className="action-strip">{message.actions.map((a, i) => <Badge key={i} tone="cyan">{a.label || a.name || String(a)}</Badge>)}</div>}
    {message.scan_id && <div className="task-chip">Scan <b>{shortId(message.scan_id)}</b></div>}
    <Expanders message={message}/>
  </article>;
}

function StatusCard({title, children, action}) {
  return <section className="status-card">
    <div className="status-title"><h3>{title}</h3>{action}</div>
    {children}
  </section>;
}

function useOpsData() {
  const [data, setData] = useState({targets: [], scans: [], findings: [], live: null, runners: null, models: null});
  const [error, setError] = useState('');
  const refresh = async () => {
    const [targets, scans, findings, live, runners, models] = await Promise.all([
      api('/targets/').catch(() => []),
      api('/scans/').catch(() => []),
      api('/findings/').catch(() => []),
      api('/live/snapshot').catch(() => null),
      api('/runners/capabilities').catch(() => null),
      api('/ai/models').catch(() => null),
    ]);
    setData({targets, scans, findings, live, runners, models});
    setError('');
  };
  useEffect(() => {
    refresh().catch(e => setError(e.message));
    const id = setInterval(() => refresh().catch(e => setError(e.message)), 4500);
    return () => clearInterval(id);
  }, []);
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
      <div className="mini-stats"><div><b>{tools}</b><span>tools</span></div><div><b>{data.models?.provider || 'gemini'}</b><span>AI</span></div><div><b>{data.models?.light_model || 'flash-lite'}</b><span>chat</span></div></div>
    </StatusCard>

    <StatusCard title="Active Target">
      <select value={selectedTargetId} onChange={e => onSelectTarget(e.target.value)}>
        <option value="">No target selected</option>
        {data.targets.map(t => <option key={t.id} value={t.id}>{t.name || t.domain}</option>)}
      </select>
      <div className="compact-copy"><b>{selectedTarget?.domain || 'No target yet'}</b><span>{truncate(selectedTarget?.scope || 'Create or select a target to run recon.', 140)}</span></div>
    </StatusCard>

    <StatusCard title="Scan Status">
      <select value={selectedScanId} onChange={e => onSelectScan(e.target.value)}>
        <option value="">No scan selected</option>
        {data.scans.map(s => <option key={s.id} value={s.id}>{shortId(s.id)} · {s.status}</option>)}
      </select>
      <div className="compact-copy"><b>{selectedScan ? `${selectedScan.mode || 'scan'} · ${selectedScan.status}` : 'Idle'}</b><span>{selectedScan ? `Phase ${selectedScan.phase || 'queued'} · ${shortId(selectedScan.id)}` : 'Start passive recon from chat actions.'}</span></div>
    </StatusCard>

    <StatusCard title="Findings">
      <div className="finding-stack">
        {data.findings.slice(0, 4).map(f => <div className="finding-card" key={f.id}><Badge tone={String(f.severity).toLowerCase()}>{f.severity || 'info'}</Badge><b>{truncate(f.title, 72)}</b><small>{f.tool || 'unknown tool'}</small></div>)}
        {!data.findings.length && <p className="muted">No parsed findings yet.</p>}
      </div>
    </StatusCard>
  </aside>;
}

function LogsDrawer({open, live}) {
  const events = useMemo(() => {
    const liveEvents = asList(live?.live_events).map(e => ({kind: e.type || 'live', message: e.message || e.payload?.message || e.payload || e, time: e.created_at}));
    const scanEvents = asList(live?.recent_scan_events).map(e => ({kind: e.level || e.tool || 'scan', message: e.message, time: e.created_at}));
    return [...liveEvents, ...scanEvents].slice(-30).reverse();
  }, [live]);
  return <section className={`logs-drawer ${open ? 'open' : ''}`}>
    <div className="drawer-handle"><span>Live logs</span><Badge>{events.length}</Badge></div>
    <div className="log-list">
      {events.map((event, i) => <div className="log-row" key={i}><span>{event.kind}</span><p>{truncate(event.message, 180)}</p></div>)}
      {!events.length && <p className="muted">No live logs yet.</p>}
    </div>
  </section>;
}

export default function App() {
  const data = useOpsData();
  const [text, setText] = useState('');
  const [busy, setBusy] = useState(false);
  const [showLogs, setShowLogs] = useState(false);
  const [selectedTargetId, setSelectedTargetId] = useState('');
  const [selectedScanId, setSelectedScanId] = useState('');
  const chatRef = useRef(null);
  const [messages, setMessages] = useState([
    {...emptyMessage, role: 'system', summary: 'BountyOS v6 Hunter Brain is ready. Ask for recon, paste a target page, or review findings. Raw execution data stays collapsed until you ask for it.'},
  ]);

  useEffect(() => { chatRef.current?.scrollTo({top: chatRef.current.scrollHeight, behavior: 'smooth'}); }, [messages]);

  const push = (message) => setMessages(prev => [...prev, {ts: new Date().toISOString(), ...message}].slice(-40));
  const runAction = async (label, fn) => {
    setBusy(true);
    try { await fn(); }
    catch (e) {
      const summary = e.status === 404 ? 'Backend endpoint not available.' : `${label} failed: ${e.message}`;
      push({...emptyMessage, role: 'assistant', summary, raw: e.payload || {error: e.message, status: e.status}});
    } finally {
      setBusy(false);
      data.refresh().catch(() => {});
    }
  };

  const send = () => runAction('Send', async () => {
    if (!text.trim()) return push({...emptyMessage, role: 'assistant', summary: 'Type a message first.'});
    const transcript = text;
    push({...emptyMessage, role: 'user', summary: transcript});
    setText('');
    const res = await api('/agent/command', {method: 'POST', body: JSON.stringify({transcript, selected_target_id: selectedTargetId || null, selected_scan_id: selectedScanId || null, source: 'dashboard'})});
    const normalized = normalizeResponse(res, 'Command completed.');
    if (normalized.target_id) setSelectedTargetId(normalized.target_id);
    if (normalized.scan_id) setSelectedScanId(normalized.scan_id);
    push({role: 'assistant', model: normalized.raw?.act?.model_used || normalized.raw?.act?.model, ...normalized});
  });

  const createTarget = () => runAction('Create target', async () => {
    const domain = text.trim().split(/\s+/)[0]?.replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!domain) return push({...emptyMessage, role: 'assistant', summary: 'Paste a domain or URL first, then create a target.'});
    const res = await api('/targets/', {method: 'POST', body: JSON.stringify({name: domain, domain, scope: domain, notes: 'Created from Hunter Brain console'})});
    setSelectedTargetId(res.id);
    push({role: 'assistant', ...normalizeResponse(res, `Target created: ${res.domain || domain}`), target_id: res.id});
  });

  const extractTarget = () => runAction('Extract target', async () => {
    if (!text.trim()) return push({...emptyMessage, role: 'assistant', summary: 'Paste target-page text first.'});
    push({...emptyMessage, role: 'user', summary: text});
    const res = await api('/ai/extract-target-page', {method: 'POST', body: JSON.stringify({text})});
    push({role: 'assistant', ...normalizeResponse(res, 'Target page extracted.')});
  });

  const passiveRecon = () => runAction('Run passive recon', async () => {
    if (!selectedTargetId) return push({...emptyMessage, role: 'assistant', summary: 'Select or create a target before starting passive recon.'});
    const res = await api('/scans/', {method: 'POST', body: JSON.stringify({target_id: selectedTargetId, mode: 'passive', config: JSON.stringify({source: 'hunter_brain_console', execution_mode: 'hybrid'})})});
    setSelectedScanId(res.id);
    push({role: 'assistant', ...normalizeResponse(res, `Passive recon started for target ${shortId(selectedTargetId)}. Task progress and logs will appear below.`), scan_id: res.id, target_id: selectedTargetId});
  });

  const approveActive = () => runAction('Approve active scan', async () => {
    const transcript = text.trim() || 'Run approved active scan for the selected target';
    if (!selectedTargetId) return push({...emptyMessage, role: 'assistant', summary: 'Select a target before approving active scan actions.'});
    const res = await api('/agent/command', {method: 'POST', body: JSON.stringify({transcript, selected_target_id: selectedTargetId, selected_scan_id: selectedScanId || null, approve: true, source: 'dashboard'})});
    const normalized = normalizeResponse(res, 'Approved active action submitted.');
    if (normalized.scan_id) setSelectedScanId(normalized.scan_id);
    push({role: 'assistant', ...normalized});
  });

  return <div className="ops-shell">
    <main className="chat-panel">
      <header className="topbar">
        <div>
          <p className="eyebrow">BountyOS v6</p>
          <h1>Hunter Brain</h1>
        </div>
        <div className="topbar-badges">
          <Badge tone={(data.runners?.online || []).length ? 'green' : 'red'}>{(data.runners?.online || []).length ? 'runner online' : 'runner offline'}</Badge>
          <Badge tone="cyan">{data.models?.chat_model || data.models?.light_model || 'gemini-2.5-flash'}</Badge>
          <Badge>{data.error ? 'API warning' : 'API live'}</Badge>
        </div>
      </header>

      <section className="chat-stream" ref={chatRef}>
        {messages.map((message, index) => <ChatMessage key={index} message={message}/>)}
      </section>

      <section className="composer">
        <textarea value={text} onChange={e => setText(e.target.value)} placeholder="Ask Hunter Brain what to do next, paste a target page, or request recon..." onKeyDown={e => { if (e.key === 'Enter' && (e.metaKey || e.ctrlKey)) send(); }}/>
        <div className="composer-actions">
          <button className="primary" onClick={send} disabled={busy}>Send</button>
          <button onClick={passiveRecon} disabled={busy}>Run Passive Recon</button>
          <button onClick={extractTarget} disabled={busy}>Extract Target</button>
          <button onClick={createTarget} disabled={busy}>Create Target</button>
          <button onClick={approveActive} disabled={busy}>Approve Active Scan</button>
          <button onClick={() => setShowLogs(v => !v)}>Show Logs</button>
        </div>
      </section>

      <LogsDrawer open={showLogs} live={data.live}/>
    </main>

    <Sidebar data={data} selectedTargetId={selectedTargetId} selectedScanId={selectedScanId} onSelectTarget={setSelectedTargetId} onSelectScan={setSelectedScanId} onRefresh={data.refresh}/>
  </div>;
}
