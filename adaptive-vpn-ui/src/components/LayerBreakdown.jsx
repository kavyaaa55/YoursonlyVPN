// src/components/LayerBreakdown.jsx
const LAYER_LABELS = [
  { key: 1, label: 'L1 — URL / Domain',     desc: 'Domain match against rule dictionary' },
  { key: 2, label: 'L2 — Packet Metadata',  desc: 'HTTP method, path keywords, Content-Type' },
  { key: 3, label: 'L3 — Content Scan',     desc: 'On-device regex scan of request body' },
  { key: 4, label: 'L4 — Message Scan',     desc: 'Keyword scan of chat / message text' },
];

export default function LayerBreakdown({ layersChecked, reason }) {
  if (!layersChecked) return null;
  return (
    <div style={{ marginTop: 20 }}>
      <h4 style={{ color: '#8B949E', marginBottom: 8, fontSize: 13, textTransform: 'uppercase', letterSpacing: 1 }}>
        Layer Breakdown
      </h4>
      {LAYER_LABELS.map(({ key, label, desc }) => {
        const checked = key <= layersChecked;
        const triggered = reason && reason.toLowerCase().includes(`layer ${key}`);
        return (
          <div key={key} style={{
            display: 'flex', alignItems: 'center', gap: 12,
            padding: '8px 12px', marginBottom: 4, borderRadius: 6,
            background: triggered ? '#1f3a2a' : checked ? '#161B22' : '#0D1117',
            border: `1px solid ${triggered ? '#06D6A0' : checked ? '#30363D' : '#21262D'}`,
            opacity: checked ? 1 : 0.4,
          }}>
            <span style={{
              width: 24, height: 24, borderRadius: '50%',
              display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: triggered ? '#06D6A0' : checked ? '#30363D' : '#21262D',
              color: triggered ? '#000' : '#fff',
              fontSize: 12, fontWeight: 'bold', flexShrink: 0,
            }}>{key}</span>
            <div>
              <div style={{ color: triggered ? '#06D6A0' : '#E6EDF3', fontSize: 13, fontWeight: triggered ? 'bold' : 'normal' }}>
                {label} {triggered && '← triggered'}
              </div>
              <div style={{ color: '#8B949E', fontSize: 11 }}>{desc}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}
