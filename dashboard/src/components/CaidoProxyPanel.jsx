import { useState, useEffect } from 'react';

const CaidoProxyPanel = () => {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    // Matches the router prefix: /api/v1/integrations/caido/ws
    const ws = new WebSocket(`${proto}//${window.location.host}/api/v1/integrations/caido/ws`);
    
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    
    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        setEvents(prev => [data, ...prev].slice(0, 50));
      } catch (e) {
        console.error("Failed to parse Caido event", e);
      }
    };

    return () => ws.close();
  }, []);

  return (
    <div className="caido-panel">
      <h3>Live Proxy Stream {connected ? '🟢' : '🔴'}</h3>
      <div className="event-list" style={{ maxHeight: '400px', overflowY: 'auto' }}>
        {events.map((ev, i) => (
          <div key={i} className="event-item" style={{ borderBottom: '1px solid #333', padding: '5px' }}>
            <strong>{ev.request.method} {ev.request.host}{ev.request.path}</strong>
            {ev.analysis && (
              <div className="analysis" style={{ fontSize: '0.8em', color: '#aaa' }}>
                {ev.analysis.summary.substring(0, 100)}...
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default CaidoProxyPanel;
