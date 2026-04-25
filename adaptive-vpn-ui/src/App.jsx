// src/App.jsx
import { useState, useRef, useEffect } from 'react';
import { classifyRequest } from './api/vpnApi';

const LEVEL_COLOR = {
  CRITICAL: '#FF4757',
  HIGH:     '#FF8C00',
  MEDIUM:   '#FFD700',
  LOW:      '#06D6A0',
};

const LEVEL_BG = {
  CRITICAL: '#2a0a0a',
  HIGH:     '#2a1500',
  MEDIUM:   '#2a2200',
  LOW:      '#0a2a1e',
};

function timestamp() {
  return new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function Badge({ level }) {
  return (
    <span style={{
      background: LEVEL_COLOR[level],
      color: level === 'MEDIUM' ? '#000' : '#fff',
      fontSize: 10, fontWeight: 'bold',
      padding: '2px 7px', borderRadius: 4,
      letterSpacing: 0.5,
    }}>{level}</span>
  );
}

function SenderPanel({ onSend, sending }) {
  const [text, setText]     = useState('');
  const [url, setUrl]       = useState('');
  const [method, setMethod] = useState('GET');
  const [isMsg, setIsMsg]   = useState(false);
  const textareaRef         = useRef(null);

  const handleSend = () => {
    if (!text.trim() && !url.trim()) return;
    onSend({ text, url, method, isMsg });
    setText('');
  };

  const handleKey = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  };

  return (
    <div style={{
      width: '50%', background: '#161B22',
      borderRight: '1px solid #30363D',
      display: 'flex', flexDirection: 'column', height: '100vh',
    }}>
      {/* Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid #30363D' }}>
        <div style={{ color: '#00B4D8', fontWeight: 'bold', fontSize: 15 }}>📤 Sender</div>
        <div style={{ color: '#555', fontSize: 12, marginTop: 2 }}>Type a message or enter a URL to send</div>
      </div>

      {/* Options */}
      <div style={{ padding: '12px 20px', borderBottom: '1px solid #21262D', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <input
          value={url}
          onChange={e => setUrl(e.target.value)}
          placeholder="URL (optional, e.g. https://uidai.gov.in)"
          style={fieldStyle}
        />
        <div style={{ display: 'flex', gap: 8 }}>
          <select value={method} onChange={e => setMethod(e.target.value)} style={{ ...fieldStyle, width: 'auto', flex: '0 0 auto' }}>
            {['GET','POST','PUT','DELETE','PATCH'].map(m => <option key={m}>{m}</option>)}
          </select>
          <label style={{ color: '#8B949E', fontSize: 13, display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
            <input type="checkbox" checked={isMsg} onChange={e => setIsMsg(e.target.checked)} />
            Chat message
          </label>
        </div>
      </div>

      {/* Quick test chips */}
      <div style={{ padding: '10px 20px', borderBottom: '1px solid #21262D', display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {[
          { label: 'Aadhaar',  url: 'https://uidai.gov.in',       text: 'Verify Aadhaar' },
          { label: 'YouTube',  url: 'https://youtube.com',         text: 'Watch video' },
          { label: 'HDFC',     url: 'https://hdfcbank.com',        text: 'Net banking' },
          { label: 'OTP msg',  url: '',                            text: 'Your OTP is 482910', isMsg: true },
          { label: 'Casual',   url: '',                            text: 'Hey! haha ok sure', isMsg: true },
          { label: 'UPI',      url: 'https://paytm.com/pay',       text: 'upi: user@oksbi' },
        ].map(q => (
          <button key={q.label} onClick={() => {
            setUrl(q.url || '');
            setText(q.text);
            setIsMsg(!!q.isMsg);
          }} style={chipStyle}>{q.label}</button>
        ))}
      </div>

      {/* Message input — grows to fill */}
      <div style={{ flex: 1, padding: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
        <textarea
          ref={textareaRef}
          value={text}
          onChange={e => setText(e.target.value)}
          onKeyDown={handleKey}
          placeholder="Type your message here… (Enter to send, Shift+Enter for newline)"
          style={{
            flex: 1, background: '#0D1117', color: '#E6EDF3',
            border: '1px solid #30363D', borderRadius: 8,
            padding: 14, fontSize: 14, resize: 'none',
            fontFamily: 'inherit', outline: 'none',
          }}
        />
        <button
          onClick={handleSend}
          disabled={sending || (!text.trim() && !url.trim())}
          style={{
            background: sending ? '#0a3a4a' : '#00B4D8',
            color: sending ? '#555' : '#000',
            border: 'none', borderRadius: 8,
            padding: '12px 0', fontWeight: 'bold', fontSize: 14,
            cursor: sending ? 'not-allowed' : 'pointer',
            transition: 'background 0.2s',
          }}
        >
          {sending ? 'Classifying…' : '⬆ Send Packet'}
        </button>
      </div>
    </div>
  );
}

function ReceiverPanel({ messages }) {
  const bottomRef = useRef(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  return (
    <div style={{
      width: '50%', background: '#0D1117',
      display: 'flex', flexDirection: 'column', height: '100vh',
    }}>
      {/* Header */}
      <div style={{ padding: '16px 20px', borderBottom: '1px solid #30363D' }}>
        <div style={{ color: '#06D6A0', fontWeight: 'bold', fontSize: 15 }}>📥 Receiver (Client)</div>
        <div style={{ color: '#555', fontSize: 12, marginTop: 2 }}>Packets arrive here with sensitivity classification</div>
      </div>

      {/* Message list */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 12 }}>
        {messages.length === 0 && (
          <div style={{ color: '#333', textAlign: 'center', marginTop: 60, fontSize: 14 }}>
            No packets yet. Send something from the left panel.
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} style={{
            background: LEVEL_BG[msg.level] || '#161B22',
            border: `1px solid ${LEVEL_COLOR[msg.level]}44`,
            borderLeft: `3px solid ${LEVEL_COLOR[msg.level]}`,
            borderRadius: 8, padding: '12px 16px',
            animation: 'fadeIn 0.3s ease',
          }}>
            {/* Top row: badge + time */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <Badge level={msg.level} />
              <span style={{ color: '#555', fontSize: 11, fontFamily: 'monospace' }}>{msg.time}</span>
            </div>

            {/* Message text */}
            {msg.text && (
              <div style={{ color: '#E6EDF3', fontSize: 14, marginBottom: 8, wordBreak: 'break-word' }}>
                {msg.text}
              </div>
            )}

            {/* URL if present */}
            {msg.url && (
              <div style={{ color: '#8B949E', fontSize: 12, marginBottom: 8, fontFamily: 'monospace' }}>
                🌐 {msg.url}
              </div>
            )}

            {/* Meta row */}
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              <MetaItem label="Reason"  value={msg.reason} />
              <MetaItem label="Layers"  value={`${msg.layers_checked} checked`} />
              <MetaItem label="Cipher"  value={msg.profile?.cipher} />
              <MetaItem label="Proto"   value={msg.profile?.proto} />
              {msg.profile?.double && <MetaItem label="Double Enc" value="✓" color="#FF4757" />}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>

      {/* Footer stats */}
      {messages.length > 0 && (
        <div style={{
          padding: '10px 20px', borderTop: '1px solid #21262D',
          display: 'flex', gap: 16, flexWrap: 'wrap',
        }}>
          {['CRITICAL','HIGH','MEDIUM','LOW'].map(lvl => {
            const count = messages.filter(m => m.level === lvl).length;
            return count > 0 ? (
              <span key={lvl} style={{ fontSize: 12, color: LEVEL_COLOR[lvl] }}>
                {lvl}: {count}
              </span>
            ) : null;
          })}
          <span style={{ fontSize: 12, color: '#555', marginLeft: 'auto' }}>
            {messages.length} total packet{messages.length !== 1 ? 's' : ''}
          </span>
        </div>
      )}
    </div>
  );
}

function MetaItem({ label, value, color }) {
  if (!value) return null;
  return (
    <span style={{ fontSize: 11 }}>
      <span style={{ color: '#555' }}>{label}: </span>
      <span style={{ color: color || '#8B949E', fontFamily: 'monospace' }}>{value}</span>
    </span>
  );
}

export default function App() {
  const [messages, setMessages] = useState([]);
  const [sending, setSending]   = useState(false);

  const handleSend = async ({ text, url, method, isMsg }) => {
    setSending(true);
    try {
      const result = await classifyRequest({
        url:     url  || null,
        method,
        body:    text || null,
        message: isMsg ? text : null,
        is_msg:  isMsg,
      });
      setMessages(prev => [...prev, {
        text,
        url,
        time:           timestamp(),
        level:          result.level,
        reason:         result.reason,
        layers_checked: result.layers_checked,
        profile:        result.profile,
      }]);
    } catch {
      setMessages(prev => [...prev, {
        text,
        url,
        time:   timestamp(),
        level:  'LOW',
        reason: '⚠ Backend unreachable — start uvicorn on port 8000',
        layers_checked: 0,
        profile: null,
      }]);
    }
    setSending(false);
  };

  return (
    <>
      <style>{`
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { background: #0D1117; font-family: system-ui, sans-serif; }
        @keyframes fadeIn { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
        ::-webkit-scrollbar { width: 6px; }
        ::-webkit-scrollbar-track { background: #0D1117; }
        ::-webkit-scrollbar-thumb { background: #30363D; border-radius: 3px; }
      `}</style>

      {/* Top bar */}
      <div style={{
        position: 'fixed', top: 0, left: 0, right: 0, zIndex: 10,
        background: '#161B22', borderBottom: '1px solid #30363D',
        padding: '10px 24px', display: 'flex', alignItems: 'center', gap: 10,
      }}>
        <span style={{ fontSize: 18 }}>🛡</span>
        <span style={{ color: '#00B4D8', fontWeight: 'bold', fontSize: 15 }}>Adaptive VPN</span>
        <span style={{ color: '#555', fontSize: 12 }}>— real-time sensitivity classification</span>
      </div>

      {/* Split layout */}
      <div style={{ display: 'flex', paddingTop: 45, height: '100vh' }}>
        <SenderPanel   onSend={handleSend} sending={sending} />
        <ReceiverPanel messages={messages} />
      </div>
    </>
  );
}

const fieldStyle = {
  width: '100%', padding: '8px 10px',
  background: '#0D1117', color: '#E6EDF3',
  border: '1px solid #30363D', borderRadius: 6,
  fontSize: 13, outline: 'none', fontFamily: 'inherit',
};

const chipStyle = {
  background: '#21262D', color: '#8B949E',
  border: '1px solid #30363D', borderRadius: 20,
  padding: '3px 10px', fontSize: 11, cursor: 'pointer',
};
