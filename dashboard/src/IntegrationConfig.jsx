import React, {useEffect, useMemo, useState} from 'react';

const API = '/api/v1';

const GROUPS = [
  {title: 'AI', items: [
    {id: 'gemini', name: 'Gemini', hint: 'Hunter Brain, planning, browser and proxy reasoning', fields: [
      {label: 'Gemini API Key', envKey: 'GEMINI_API_KEY', type: 'secret'},
      {label: 'Chat Model', envKey: 'BOUNTYOS_CHAT_MODEL', type: 'text', placeholder: 'gemini-2.5-flash-lite'},
      {label: 'Agentic Model', envKey: 'BOUNTYOS_AGENTIC_MODEL', type: 'text', placeholder: 'gemini-3.5-flash'},
    ]},
  ]},
  {title: 'Browser and Proxy', items: [
    {id: 'browser', name: 'Chrome DevTools MCP', hint: 'Current page, console logs, network requests and JS endpoints', fields: [
      {label: 'MCP URL', envKey: 'CHROME_DEVTOOLS_MCP_URL', type: 'text', placeholder: 'http://127.0.0.1:9222'},
    ]},
    {id: 'caido', name: 'Caido', hint: 'Proxy history import and selected request analysis', fields: [
      {label: 'Caido URL', envKey: 'CAIDO_URL', type: 'text', placeholder: 'http://127.0.0.1:8080'},
      {label: 'Caido Token', envKey: 'CAIDO_API_TOKEN', type: 'secret'},
    ]},
    {id: 'burp', name: 'Burp Suite', hint: 'Burp REST API integration', fields: [
      {label: 'Burp URL', envKey: 'BURP_URL', type: 'text', placeholder: 'http://127.0.0.1:1337'},
      {label: 'Burp API Key', envKey: 'BURP_APIKEY', type: 'secret'},
    ]},
    {id: 'zap', name: 'OWASP ZAP', hint: 'ZAP spider, alerts and import flow', fields: [
      {label: 'ZAP URL', envKey: 'ZAP_URL', type: 'text', placeholder: 'http://127.0.0.1:8090'},
      {label: 'ZAP API Key', envKey: 'ZAP_APIKEY', type: 'secret'},
    ]},
  ]},
  {title: 'Bug Bounty Platforms', items: [
    {id: 'hackerone', name: 'HackerOne', hint: 'Program and report sync', fields: [
      {label: 'API Username', envKey: 'HACKERONE_API_USERNAME', type: 'text'},
      {label: 'API Token', envKey: 'HACKERONE_API_TOKEN', type: 'secret'},
    ]},
    {id: 'bugcrowd', name: 'Bugcrowd', hint: 'Program and submission sync', fields: [
      {label: 'API Token', envKey: 'BUGCROWD_API_TOKEN', type: 'secret'},
    ]},
    {id: 'intigriti', name: 'Intigriti', hint: 'OAuth credentials, manual verification', fields: [
      {label: 'Client ID', envKey: 'INTIGRITI_CLIENT_ID', type: 'text'},
      {label: 'Client Secret', envKey: 'INTIGRITI_CLIENT_SECRET', type: 'secret'},
    ]},
    {id: 'yeswehack', name: 'YesWeHack', hint: 'Manual/session based setup for now', fields: [
      {label: 'API Key', envKey: 'YESWEHACK_API_KEY', type: 'secret'},
    ]},
  ]},
  {title: 'Notifications and Git', items: [
    {id: 'discord', name: 'Discord', hint: 'Webhook alerts', fields: [{label: 'Webhook URL', envKey: 'DISCORD_WEBHOOK_URL', type: 'secret'}]},
    {id: 'telegram', name: 'Telegram', hint: 'Bot notifications', fields: [
      {label: 'Bot Token', envKey: 'TELEGRAM_BOT_TOKEN', type: 'secret'},
      {label: 'Chat ID', envKey: 'TELEGRAM_CHAT_ID', type: 'text'},
    ]},
    {id: 'slack', name: 'Slack', hint: 'Webhook alerts', fields: [{label: 'Webhook URL', envKey: 'SLACK_WEBHOOK_URL', type: 'secret'}]},
    {id: 'github', name: 'GitHub', hint: 'Repository automation token', fields: [{label: 'GitHub Token', envKey: 'GITHUB_TOKEN', type: 'secret'}]},
  ]},
];

function statusTone(status) {
  if (status === 'connected') return 'green';
  if (status === 'testing' || status === 'manual') return 'amber';
  if (status === 'failed' || status === 'error') return 'red';
  return 'neutral';
}

function SecretInput({field, value, remote, onChange, onSave}) {
  const [show, setShow] = useState(false);
  const secret = field.type === 'secret';
  return <label className="integration-field">
    <span>{field.label} {remote?.set && <em>saved {remote.masked}</em>}</span>
    <div className="secret-row">
      <input type={secret && !show ? 'password' : 'text'} value={value || ''} placeholder={field.placeholder || ''} onChange={e => onChange(e.target.value)} onBlur={e => onSave(e.target.value)} />
      {secret && <button type="button" onClick={() => setShow(v => !v)}>{show ? 'Hide' : 'Show'}</button>}
    </div>
  </label>;
}

function IntegrationCard({item, remote, values, status, onChange, onSave, onTest}) {
  const filled = item.fields.every(f => values?.[f.envKey] || remote?.[f.envKey]?.set);
  return <div className="integration-card">
    <div className="integration-head">
      <div><b>{item.name}</b><span>{item.hint}</span></div>
      <span className={`badge ${statusTone(status)}`}>{status || 'not connected'}</span>
    </div>
    <div className="integration-fields">
      {item.fields.map(field => <SecretInput key={field.envKey} field={field} value={values?.[field.envKey]} remote={remote?.[field.envKey]} onChange={value => onChange(item.id, field.envKey, value)} onSave={value => onSave(field.envKey, value)} />)}
    </div>
    <button disabled={!filled || status === 'testing'} onClick={() => onTest(item.id)}>{status === 'testing' ? 'Testing...' : 'Test connection'}</button>
  </div>;
}

export default function IntegrationConfig() {
  const [remote, setRemote] = useState({});
  const [values, setValues] = useState({});
  const [status, setStatus] = useState({});
  const [error, setError] = useState('');

  const load = async () => {
    try {
      const res = await fetch(`${API}/integrations/config`);
      const data = await res.json();
      setRemote(data.integrations || {});
      setError('');
    } catch (e) {
      setError('Unable to load integration config API. Rebuild the backend image.');
    }
  };

  useEffect(() => { load(); }, []);

  const onChange = (id, envKey, value) => setValues(prev => ({...prev, [id]: {...(prev[id] || {}), [envKey]: value}}));
  const onSave = async (envKey, value) => {
    if (!value) return;
    try {
      const res = await fetch(`${API}/integrations/config/save`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({env_key: envKey, value})});
      if (!res.ok) throw new Error(await res.text());
      await load();
    } catch (e) {
      setError(`Save failed for ${envKey}`);
    }
  };
  const onTest = async id => {
    setStatus(prev => ({...prev, [id]: 'testing'}));
    try {
      const res = await fetch(`${API}/integrations/config/test/${id}`, {method: 'POST'});
      const data = await res.json();
      setStatus(prev => ({...prev, [id]: data.status || 'failed'}));
    } catch (e) {
      setStatus(prev => ({...prev, [id]: 'error'}));
    }
  };

  const sessionEnv = useMemo(() => Object.values(values).flatMap(group => Object.entries(group || {}).filter(([, v]) => v).map(([k, v]) => `${k}=${v}`)).join('\n'), [values]);

  return <section className="page-card integrations-config">
    <div className="page-heading"><div><h2>Integrations</h2><p className="muted">Connect AI, browser, proxy tools, bounty platforms, notifications and Git. Secrets are masked after save.</p></div><button onClick={load}>Refresh</button></div>
    {error && <div className="warning-box">{error}</div>}
    <div className="integration-layout">
      <div className="integration-groups">
        {GROUPS.map(group => <div key={group.title} className="integration-section"><h3>{group.title}</h3><div className="integration-grid">{group.items.map(item => <IntegrationCard key={item.id} item={item} remote={remote[item.id]} values={values[item.id]} status={status[item.id]} onChange={onChange} onSave={onSave} onTest={onTest} />)}</div></div>)}
      </div>
      <aside className="env-preview"><h3>This session</h3><pre>{sessionEnv || '# Type and blur a field to save it into backend .env'}</pre><p className="muted">Saved values are stored server-side and shown masked after refresh.</p></aside>
    </div>
  </section>;
}
