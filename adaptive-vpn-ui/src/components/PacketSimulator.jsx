// src/components/PacketSimulator.jsx
import { useState } from 'react';
import { classifyRequest } from '../api/vpnApi';
import SensitivityBadge from './SensitivityBadge';
import CipherProfile from './CipherProfile';
import LayerBreakdown from './LayerBreakdown';

const QUICK_TESTS = [
  { label: 'Aadhaar Portal',  url: 'https://uidai.gov.in/verify',          method: 'GET',  body: '' },
  { label: 'Steam Gaming',    url: 'https://steampowered.com/game/123',     method: 'GET',  body: '' },
  { label: 'Login w/ PW',     url: 'https://api.example.com/login',         method: 'POST', body: '{"password": "mySecret123"}' },
  { label: 'HDFC Bank',       url: 'https://hdfcbank.com/netbanking',        method: 'GET',  body: '' },
  { label: 'YouTube Stream',  url: 'https://youtube.com/watch?v=abc',        method: 'GET',  body: '' },
  { label: 'UPI Transfer',    url: 'https://paytm.com/pay',                  method: 'POST', body: '{"upi": "user@oksbi", "amount": 500}' },
];

export default function PacketSimulator() {
  const [url, setUrl]         = useState('');
  const [method, setMethod]   = useState('GET');
  const [body, setBody]       = useState('');
  const [message, setMessage] = useState('');
  const [isMsg, setIsMsg]     = useState(false);
  const [result, setResult]   = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState(null);

  const handleSimulate = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await classifyRequest({
        url: url || null,
        method,
        body: body || null,
        message: message || null,
        is_msg: isMsg,
      });
      setResult(data);
    } catch (e) {
      setError('Could not reach backend. Make sure the API server is running on port 8000.');
    }
    setLoading(false);
  };

  const loadQuickTest = (test) => {
    setUrl(test.url);
    setMethod(test.method);
    setBody(test.body);
    setIsMsg(false);
    setMessage('');
    setResult(null);
  };

  return (
    <div style={{ background: '#161B22', padding: 24, borderRadius: 12, maxWidth: 700 }}>
      <h2 style={{ color: '#00B4D8', marginTop: 0 }}>Packet Simulator</h2>

      {/* Quick test buttons */}
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 16 }}>
        {QUICK_TESTS.map((t) => (
          <button key={t.label} onClick={() => loadQuickTest(t)}
            style={{ background: '#21262D', color: '#8B949E', border: '1px solid #30363D',
              padding: '4px 12px', borderRadius: 6, cursor: 'pointer', fontSize: 12 }}>
            {t.label}
          </button>
        ))}
      </div>

      <input value={url} onChange={e => setUrl(e.target.value)}
        placeholder="Enter URL (e.g. https://uidai.gov.in)"
        style={inputStyle} />

      <select value={method} onChange={e => setMethod(e.target.value)} style={inputStyle}>
        {['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].map(m => <option key={m}>{m}</option>)}
      </select>

      <textarea value={body} onChange={e => setBody(e.target.value)}
        placeholder="Request body (optional JSON, form data, etc.)"
        rows={3} style={inputStyle} />

      <label style={{ color: '#ccc', display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
        <input type="checkbox" checked={isMsg} onChange={e => setIsMsg(e.target.checked)} />
        This is a chat / message
      </label>

      {isMsg && (
        <input value={message} onChange={e => setMessage(e.target.value)}
          placeholder="Message text (e.g. 'Your OTP is 123456')"
          style={inputStyle} />
      )}

      <button onClick={handleSimulate} disabled={loading}
        style={{ background: '#00B4D8', color: '#000', padding: '10px 28px',
          borderRadius: 8, border: 'none', fontWeight: 'bold', cursor: 'pointer',
          opacity: loading ? 0.7 : 1 }}>
        {loading ? 'Classifying...' : 'Simulate Packet'}
      </button>

      {error && (
        <p style={{ color: '#FF4757', marginTop: 12, fontSize: 13 }}>{error}</p>
      )}

      {result && (
        <div style={{ marginTop: 24 }}>
          <SensitivityBadge level={result.level} />
          <p style={{ color: '#aaa', marginTop: 12 }}>
            <strong style={{ color: '#E6EDF3' }}>Reason:</strong> {result.reason}
          </p>
          <p style={{ color: '#aaa', marginTop: 4 }}>
            <strong style={{ color: '#E6EDF3' }}>Layers checked:</strong> {result.layers_checked}
          </p>
          <LayerBreakdown layersChecked={result.layers_checked} reason={result.reason} />
          <CipherProfile profile={result.profile} />
        </div>
      )}
    </div>
  );
}

const inputStyle = {
  width: '100%', padding: 10, marginBottom: 12,
  background: '#0D1117', color: '#fff', border: '1px solid #30363D',
  borderRadius: 6, fontSize: 14, boxSizing: 'border-box',
};
