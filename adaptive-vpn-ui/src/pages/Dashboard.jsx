// src/pages/Dashboard.jsx
import { useEffect, useState } from 'react';
import { getProfiles } from '../api/vpnApi';
import LiveFeed from '../components/LiveFeed';
import SensitivityBadge from '../components/SensitivityBadge';

const LEVEL_ORDER = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];

export default function Dashboard() {
  const [profiles, setProfiles] = useState(null);

  useEffect(() => {
    getProfiles().then(setProfiles).catch(() => {});
  }, []);

  return (
    <div style={{ padding: 24, maxWidth: 1100, margin: '0 auto' }}>
      <h1 style={{ color: '#E6EDF3', marginTop: 0 }}>Dashboard</h1>
      <p style={{ color: '#8B949E', marginBottom: 32 }}>
        Real-time adaptive encryption based on data sensitivity. All classification runs on-device.
      </p>

      {/* Encryption profiles table */}
      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: '#00B4D8', fontSize: 16, marginBottom: 16 }}>Encryption Profiles</h2>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: 16 }}>
          {profiles
            ? LEVEL_ORDER.map((level) => {
                const p = profiles[level];
                return (
                  <div key={level} style={{
                    background: '#161B22', border: '1px solid #30363D',
                    borderRadius: 10, padding: 16,
                  }}>
                    <SensitivityBadge level={level} />
                    <div style={{ marginTop: 12, fontSize: 13, color: '#8B949E', lineHeight: 1.8 }}>
                      <div><span style={{ color: '#E6EDF3' }}>Cipher:</span> {p.cipher}</div>
                      <div><span style={{ color: '#E6EDF3' }}>TLS:</span> {p.tls}</div>
                      <div><span style={{ color: '#E6EDF3' }}>Protocol:</span> {p.proto}</div>
                      <div><span style={{ color: '#E6EDF3' }}>PFS:</span> {p.pfs ? 'Yes' : 'No'}</div>
                      <div><span style={{ color: '#E6EDF3' }}>Double Enc:</span> {p.double ? 'Yes' : 'No'}</div>
                      <div><span style={{ color: '#E6EDF3' }}>Latency:</span> {p.latency || 'N/A'}</div>
                    </div>
                  </div>
                );
              })
            : <p style={{ color: '#555' }}>Loading profiles... (backend must be running)</p>
          }
        </div>
      </section>

      {/* Layer reference */}
      <section style={{ marginBottom: 40 }}>
        <h2 style={{ color: '#00B4D8', fontSize: 16, marginBottom: 16 }}>Detection Layers</h2>
        <div style={{ background: '#161B22', border: '1px solid #30363D', borderRadius: 10, overflow: 'hidden' }}>
          {[
            ['L1 — URL / Domain',    'Domain & subdomain match against rule dictionary. Fastest — no content read.'],
            ['L2 — Packet Metadata', 'HTTP method, URL path keywords, Content-Type header.'],
            ['L3 — Content Scan',    'On-device regex scan of request body — Aadhaar, PAN, UPI, credit cards, etc.'],
            ['L4 — Message Scan',    'Keyword scan of chat messages — OTP, IFSC, password, bank terms, etc.'],
          ].map(([layer, desc], i) => (
            <div key={layer} style={{
              display: 'flex', gap: 16, padding: '14px 20px',
              borderBottom: i < 3 ? '1px solid #21262D' : 'none',
            }}>
              <span style={{
                color: '#00B4D8', fontWeight: 'bold', fontSize: 13,
                minWidth: 180, fontFamily: 'monospace',
              }}>{layer}</span>
              <span style={{ color: '#8B949E', fontSize: 13 }}>{desc}</span>
            </div>
          ))}
        </div>
      </section>

      {/* Live feed */}
      <section>
        <h2 style={{ color: '#00B4D8', fontSize: 16, marginBottom: 16 }}>Live Packet Feed</h2>
        <LiveFeed />
      </section>
    </div>
  );
}
