// src/components/SensitivityBadge.jsx
const COLORS = {
  CRITICAL: { bg: '#FF4757', text: '#fff', border: '#FF4757' },
  HIGH:     { bg: '#FF8C00', text: '#fff', border: '#FF8C00' },
  MEDIUM:   { bg: '#FFD700', text: '#000', border: '#FFD700' },
  LOW:      { bg: '#06D6A0', text: '#000', border: '#06D6A0' },
};

export default function SensitivityBadge({ level }) {
  const c = COLORS[level] || COLORS.LOW;
  return (
    <div style={{
      display: 'inline-flex', alignItems: 'center', gap: 8,
      background: c.bg, color: c.text,
      padding: '8px 20px', borderRadius: 8,
      fontWeight: 'bold', fontSize: 18,
      boxShadow: `0 0 12px ${c.bg}88`
    }}>
      {level}
    </div>
  );
}
