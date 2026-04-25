// src/components/LiveFeed.jsx
import { useEffect, useState } from 'react';
import { createWebSocket } from '../api/vpnApi';
import SensitivityBadge from './SensitivityBadge';

const LEVEL_COLOR = {
  CRITICAL: '#FF4757', HIGH: '#FF8C00', MEDIUM: '#FFD700', LOW: '#06D6A0',
};

export default function LiveFeed() {
  const [events, setEvents] = useState([]);
  const [connected, setConnected] = useState(false);

  useEffect(() => {
    let ws;
    try {
      ws = createWebSocket((data) => {
        setEvents(prev => [
          { ...data, time: new Date().toLocaleTimeString() },
          ...prev.slice(0, 49), // Keep last 50
        ]);
      });
      ws.onopen  = () => setConnected(true);
      ws.onclose = () => setConnected(false);
      ws.onerror = () => setConnected(false);
    } catch (e) {
      setConnected(false);
    }
    return () => ws && ws.close();
  }, []);

  return (
    <div style={{ background: '#0D1117', borderRadius: 12, padding: 20 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
        <h3 style={{ color: '#00B4D8', margin: 0 }}>Live Packet Feed</h3>
        <span style={{
          width: 8, height: 8, borderRadius: '50%',
          background: connected ? '#06D6A0' : '#FF4757',
          display: 'inline-block',
        }} />
        <span style={{ color: connected ? '#06D6A0' : '#FF4757', fontSize: 12 }}>
          {connected ? 'Connected' : 'Disconnected'}
        </span>
      </div>

      {!connected && (
        <p style={{ color: '#555', fontSize: 13 }}>
          WebSocket not connected. Start the backend server on port 8000.
        </p>
      )}

      {connected && events.length === 0 && (
        <p style={{ color: '#555' }}>Waiting for packets...</p>
      )}

      {events.map((e, i) => (
        <div key={i} style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '8px 0', borderBottom: '1px solid #21262D',
        }}>
          <span style={{ color: '#555', fontSize: 12, minWidth: 70 }}>{e.time}</span>
          <span style={{
            background: (LEVEL_COLOR[e.level] || '#555') + '22',
            color: LEVEL_COLOR[e.level] || '#555',
            padding: '2px 10px', borderRadius: 4, fontWeight: 'bold', fontSize: 12,
          }}>{e.level}</span>
          <span style={{ color: '#8B949E', fontSize: 13 }}>{e.reason}</span>
        </div>
      ))}
    </div>
  );
}
