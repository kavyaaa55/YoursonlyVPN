// src/components/CipherProfile.jsx
export default function CipherProfile({ profile }) {
  if (!profile) return null;
  const rows = [
    ['Cipher',     profile.cipher],
    ['TLS',        profile.tls],
    ['Protocol',   profile.proto],
    ['PFS',        profile.pfs ? 'Yes' : 'No'],
    ['Cert Pin',   profile.cert_pin ? 'Yes' : 'No'],
    ['Double Enc', profile.double ? 'Yes' : 'No'],
    ['Target Lat', profile.latency || 'N/A'],
  ];
  return (
    <table style={{ marginTop: 16, width: '100%', borderCollapse: 'collapse' }}>
      <tbody>
        {rows.map(([k, v]) => (
          <tr key={k} style={{ borderBottom: '1px solid #30363D' }}>
            <td style={{ color: '#8B949E', padding: '6px 12px' }}>{k}</td>
            <td style={{ color: '#E6EDF3', padding: '6px 12px', fontFamily: 'monospace' }}>{v}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
