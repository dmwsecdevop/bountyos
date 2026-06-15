import React, { useEffect, useMemo, useState } from 'react'
import { api } from '../lib/api'

const card = { background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:14 }
const mono = { fontFamily:'var(--font-mono)' }

function Pill({ children, color='var(--accent)' }) {
  return <span style={{...mono, fontSize:10, color, border:`1px solid ${color}55`, borderRadius:2, padding:'2px 7px', background:`${color}12`}}>{children}</span>
}

const PLATFORMS = [
  ['hackerone', 'HackerOne'],
  ['bugcrowd', 'Bugcrowd'],
  ['intigriti', 'Intigriti'],
  ['yeswehack', 'YesWeHack'],
  ['custom', 'Custom JSON API'],
]

export default function BountyAccounts() {
  const [snapshot, setSnapshot] = useState(null)
  const [accounts, setAccounts] = useState([])
  const [caps, setCaps] = useState(null)
  const [health, setHealth] = useState(null)
  const [busy, setBusy] = useState('')
  const [result, setResult] = useState(null)
  const [filter, setFilter] = useState('')
  const [form, setForm] = useState({
    platform: 'hackerone',
    display_name: 'My HackerOne',
    username: '',
    token_secret: '',
    auth_type: '',
    api_base_url: '',
    notes: '',
  })

  const refresh = async () => {
    const [snap, list, cap, healthSnap] = await Promise.all([
      api.accounts.snapshot().catch(()=>null),
      api.accounts.list().catch(()=>[]),
      api.accounts.capabilities().catch(()=>null),
      api.connectorHealth.snapshot().catch(()=>null),
    ])
    setSnapshot(snap)
    setAccounts(list)
    setCaps(cap)
    setHealth(healthSnap)
  }

  useEffect(() => { refresh() }, [])

  const defaults = caps?.platforms?.[form.platform]

  const onPlatform = (platform) => {
    const def = caps?.platforms?.[platform]
    setForm(f => ({
      ...f,
      platform,
      display_name: platform === 'custom' ? 'Custom Bounty Feed' : `My ${def?.label || platform}`,
      auth_type: def?.auth || '',
      api_base_url: def?.base_url || '',
    }))
  }

  const create = async () => {
    setBusy('create')
    try {
      const payload = {...form}
      if (!payload.token_secret) delete payload.token_secret
      if (!payload.auth_type) delete payload.auth_type
      if (!payload.api_base_url) delete payload.api_base_url
      const res = await api.accounts.create(payload)
      setResult({ created: res })
      setForm(f => ({...f, token_secret:''}))
      await refresh()
    } catch (e) { setResult({ error:e.message }) }
    finally { setBusy('') }
  }

  const test = async (id) => {
    setBusy('test:'+id)
    try { setResult(await api.accounts.test(id)); await refresh() }
    catch (e) { setResult({ error:e.message }) }
    finally { setBusy('') }
  }

  const sync = async (id) => {
    setBusy('sync:'+id)
    try { setResult(await api.accounts.sync(id, { max_items: 200 })); await refresh() }
    catch (e) { setResult({ error:e.message }) }
    finally { setBusy('') }
  }

  const syncAll = async () => {
    setBusy('sync-all')
    try { setResult(await api.accounts.syncAll({ max_items: 200 })); await refresh() }
    catch (e) { setResult({ error:e.message }) }
    finally { setBusy('') }
  }

  const remove = async (id) => {
    setBusy('delete:'+id)
    try { setResult(await api.accounts.delete(id)); await refresh() }
    catch (e) { setResult({ error:e.message }) }
    finally { setBusy('') }
  }

  const filtered = useMemo(() => {
    const q = filter.toLowerCase().trim()
    if (!q) return accounts
    return accounts.filter(a => `${a.display_name} ${a.platform} ${a.username} ${a.status}`.toLowerCase().includes(q))
  }, [accounts, filter])

  return <div style={{padding:20, display:'flex', flexDirection:'column', gap:14}}>
    <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', gap:12}}>
      <div>
        <div style={{...mono, color:'var(--accent)', letterSpacing:2, fontSize:14}}>// BOUNTY ACCOUNT HUB</div>
        <div style={{fontSize:12, color:'var(--text-muted)', marginTop:4}}>Connect HackerOne, Bugcrowd, Intigriti, YesWeHack or custom API feeds with tokens. BountyOS syncs programs/scope your account can access.</div>
      </div>
      <div style={{display:'flex', gap:8, alignItems:'center'}}>
        <Pill color='var(--green)'>{snapshot?.connected_accounts || 0} CONNECTED</Pill>
        <Pill color='var(--yellow)'>{snapshot?.connected_programs || 0} PROGRAMS</Pill>
        <Pill color={(health?.counts?.auth_error || health?.counts?.unavailable || health?.counts?.rate_limited) ? 'var(--red)' : 'var(--green)'}>{health?.total || 0} API HEALTH</Pill>
      </div>
    </div>

    <div style={{display:'grid', gridTemplateColumns:'1fr .9fr', gap:14}}>
      <div style={card}>
        <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>CONNECT ACCOUNT</div>
        <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:10}}>
          <label style={label}>Platform
            <select value={form.platform} onChange={e=>onPlatform(e.target.value)} style={input}>
              {PLATFORMS.map(([id,label]) => <option key={id} value={id}>{label}</option>)}
            </select>
          </label>
          <label style={label}>Display name
            <input value={form.display_name} onChange={e=>setForm({...form, display_name:e.target.value})} style={input} />
          </label>
          <label style={label}>Username / token identifier
            <input value={form.username} onChange={e=>setForm({...form, username:e.target.value})} placeholder='H1 token identifier or account label' style={input} />
          </label>
          <label style={label}>Auth type
            <select value={form.auth_type || defaults?.auth || ''} onChange={e=>setForm({...form, auth_type:e.target.value})} style={input}>
              <option value=''>platform default</option>
              <option value='api_token'>API/Bearer token</option>
              <option value='oauth_bearer'>OAuth bearer</option>
              <option value='basic_token'>Basic token</option>
              <option value='custom'>Custom</option>
            </select>
          </label>
          <label style={{...label, gridColumn:'1 / span 2'}}>API base URL
            <input value={form.api_base_url || defaults?.base_url || ''} onChange={e=>setForm({...form, api_base_url:e.target.value})} placeholder='Optional; platform default used when blank' style={input} />
          </label>
          <label style={{...label, gridColumn:'1 / span 2'}}>API/OAuth token secret
            <input value={form.token_secret} onChange={e=>setForm({...form, token_secret:e.target.value})} type='password' placeholder='Paste token. BountyOS will not show it again.' style={input} />
          </label>
          <label style={{...label, gridColumn:'1 / span 2'}}>Notes / custom paths
            <input value={form.notes} onChange={e=>setForm({...form, notes:e.target.value})} placeholder='Optional. For custom endpoints: paths=/v1/programs,/v1/invites' style={input} />
          </label>
        </div>
        <div style={{display:'flex', gap:8, marginTop:12, alignItems:'center'}}>
          <button onClick={create} disabled={busy==='create' || !form.display_name} className='btn-primary'>{busy==='create' ? 'SAVING...' : 'SAVE ACCOUNT'}</button>
          <button onClick={syncAll} disabled={busy==='sync-all'} className='btn'>{busy==='sync-all' ? 'SYNCING...' : 'SYNC ALL'}</button>
        </div>
        <div style={{fontSize:11, color:'var(--text-muted)', marginTop:12, lineHeight:1.6}}>Use official API/OAuth tokens, not platform passwords. API access differs by platform and account permissions; if an endpoint is blocked, the result will show the HTTP error.</div>
      </div>

      <div style={card}>
        <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>CONNECTED MODE</div>
        <div style={{display:'grid', gridTemplateColumns:'repeat(2,1fr)', gap:8}}>
          <Stat label='Accounts' value={snapshot?.total_accounts || 0} />
          <Stat label='Connected' value={snapshot?.connected_accounts || 0} />
          <Stat label='Private/Connected Programs' value={snapshot?.connected_programs || 0} />
          <Stat label='Platforms' value={Object.keys(snapshot?.platforms || {}).length} />
        </div>
        <div style={{height:1, background:'var(--border)', margin:'12px 0'}} />
        <div style={{fontSize:12, color:'var(--text-dim)', lineHeight:1.65}}>Connector health:</div>
        <div style={{display:'flex', flexDirection:'column', gap:6, marginTop:8}}>
          {(health?.connectors || []).filter(x => ['hackerone','bugcrowd','intigriti','yeswehack'].includes(x.provider)).map(x => <div key={x.provider} style={{display:'flex', justifyContent:'space-between', gap:8, fontSize:11, ...mono}}>
            <span style={{color:'var(--text-dim)'}}>{x.provider}</span>
            <span style={{color:healthColor(x.status)}}>{String(x.status).toUpperCase()}</span>
          </div>)}
          {!health?.connectors?.length && <div style={{fontSize:11, color:'var(--text-muted)'}}>Health appears after the first test/sync request.</div>}
        </div>
        <div style={{height:1, background:'var(--border)', margin:'12px 0'}} />
        <div style={{fontSize:12, color:'var(--text-dim)', lineHeight:1.65}}>Chat agent commands:</div>
        <pre style={{...mono, whiteSpace:'pre-wrap', color:'var(--text-muted)', fontSize:11, marginTop:8}}>sync bounty accounts
check my bugcrowd programs
show bounty accounts
show private invites
add program targets</pre>
      </div>
    </div>

    <div style={card}>
      <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', marginBottom:10, gap:10}}>
        <div style={{...mono, color:'var(--accent)', fontSize:12}}>ACCOUNTS</div>
        <input value={filter} onChange={e=>setFilter(e.target.value)} placeholder='filter accounts...' style={{...input, minWidth:260}} />
      </div>
      <div style={{display:'grid', gridTemplateColumns:'repeat(auto-fill, minmax(330px, 1fr))', gap:10}}>
        {filtered.map(a => <AccountCard key={a.id} a={a} busy={busy} onTest={()=>test(a.id)} onSync={()=>sync(a.id)} onDelete={()=>remove(a.id)} />)}
        {!filtered.length && <div style={{color:'var(--text-muted)', fontSize:12}}>No connected accounts yet.</div>}
      </div>
    </div>

    <div style={card}>
      <div style={{...mono, color:'var(--accent)', fontSize:12, marginBottom:10}}>LAST RESULT</div>
      {result ? <ActionResult result={result} /> : <div style={{fontSize:12, color:'var(--text-muted)'}}>No account action yet.</div>}
    </div>
  </div>
}

const label = { display:'flex', flexDirection:'column', gap:5, color:'var(--text-dim)', fontSize:11, ...mono }
const input = { background:'var(--bg-input)', border:'1px solid var(--border)', color:'var(--text-primary)', borderRadius:'var(--radius)', padding:'8px 9px', ...mono, fontSize:11 }

function Stat({ label, value }) {
  return <div style={{background:'var(--bg-input)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:10}}>
    <div style={{...mono, color:'var(--text-muted)', fontSize:10}}>{label}</div>
    <div style={{...mono, color:'var(--accent)', fontSize:18, marginTop:3}}>{value}</div>
  </div>
}

function healthColor(status) {
  if (status === 'connected' || status === 'healthy') return 'var(--green)'
  if (status === 'rate_limited') return 'var(--yellow)'
  if (['token_expired','access_denied','auth_error','error'].includes(status)) return 'var(--red)'
  if (['unavailable','degraded'].includes(status)) return 'var(--purple)'
  return 'var(--yellow)'
}

function ActionResult({ result }) {
  const summary = result?.summary || result
  const details = summary?.error_details || []
  const status = summary?.status || (result?.ok === false ? 'error' : 'complete')
  const retryAfter = summary?.retry_after_seconds
  return <div style={{background:'var(--bg-input)', border:`1px solid ${healthColor(status)}66`, borderRadius:'var(--radius)', padding:11}}>
    <div style={{display:'flex', justifyContent:'space-between', alignItems:'center', gap:8}}>
      <Pill color={healthColor(status)}>{String(status).toUpperCase()}</Pill>
      {summary?.attempts != null && <span style={{...mono, fontSize:10, color:'var(--text-muted)'}}>attempts: {summary.attempts}</span>}
    </div>
    {retryAfter != null && <div style={{marginTop:8, color:'var(--yellow)', fontSize:11}}>Rate limit active. Suggested retry in about {retryAfter} seconds.</div>}
    {details.map((d,i) => <div key={i} style={{marginTop:8, padding:8, border:'1px solid var(--border)', borderRadius:'var(--radius)'}}>
      <div style={{...mono, color:healthColor(d.code === 'rate_limited' ? 'rate_limited' : d.code?.includes('token') || d.code === 'access_denied' ? 'error' : 'unavailable'), fontSize:10}}>{String(d.code || 'error').toUpperCase()}</div>
      <div style={{fontSize:11, color:'var(--text-dim)', marginTop:4}}>{d.message}</div>
      {d.status_code && <div style={{...mono, fontSize:10, color:'var(--text-muted)', marginTop:3}}>HTTP {d.status_code} · retryable {String(Boolean(d.retryable))}</div>}
    </div>)}
    {!details.length && <pre style={{margin:'9px 0 0', maxHeight:230, overflow:'auto', whiteSpace:'pre-wrap', wordBreak:'break-word', color:'var(--text-dim)', fontSize:11}}>{JSON.stringify(result, null, 2)}</pre>}
  </div>
}

function AccountCard({ a, busy, onTest, onSync, onDelete }) {
  const statusColor = healthColor(a.status)
  return <div style={{background:'var(--bg-input)', border:'1px solid var(--border)', borderRadius:'var(--radius)', padding:12, display:'flex', flexDirection:'column', gap:8}}>
    <div style={{display:'flex', justifyContent:'space-between', gap:8, alignItems:'flex-start'}}>
      <div>
        <div style={{color:'var(--text-primary)', fontWeight:700, fontSize:13}}>{a.display_name}</div>
        <div style={{...mono, color:'var(--text-muted)', fontSize:10, marginTop:3}}>{a.platform} · {a.auth_type}</div>
      </div>
      <Pill color={statusColor}>{a.status?.toUpperCase?.() || 'CREATED'}</Pill>
    </div>
    <div style={{display:'grid', gridTemplateColumns:'1fr 1fr', gap:6, fontSize:11, color:'var(--text-muted)'}}>
      <div><b style={{color:'var(--text-dim)'}}>user:</b> {a.username || '—'}</div>
      <div><b style={{color:'var(--text-dim)'}}>token:</b> {a.token_label || (a.has_token ? 'stored' : 'not set')}</div>
      <div style={{gridColumn:'1 / span 2', wordBreak:'break-all'}}><b style={{color:'var(--text-dim)'}}>api:</b> {a.api_base_url || 'platform default'}</div>
      <div style={{gridColumn:'1 / span 2'}}><b style={{color:'var(--text-dim)'}}>last sync:</b> {(a.last_sync_at || '').replace('T',' ').slice(0,16) || 'never'}</div>
      {a.last_error && <div style={{gridColumn:'1 / span 2', color:'var(--red)'}}>{a.last_error}</div>}
    </div>
    <div style={{display:'flex', gap:6, marginTop:4}}>
      <button onClick={onTest} disabled={busy==='test:'+a.id} className='btn' style={{fontSize:10, padding:'5px 8px'}}>{busy==='test:'+a.id ? 'TESTING...' : 'TEST'}</button>
      <button onClick={onSync} disabled={busy==='sync:'+a.id} className='btn-primary' style={{fontSize:10, padding:'5px 8px'}}>{busy==='sync:'+a.id ? 'SYNCING...' : 'SYNC'}</button>
      <button onClick={onDelete} disabled={busy==='delete:'+a.id} className='btn' style={{fontSize:10, padding:'5px 8px', marginLeft:'auto'}}>DELETE</button>
    </div>
  </div>
}
