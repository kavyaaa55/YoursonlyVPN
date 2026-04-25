// src/pages/Simulator.jsx
import PacketSimulator from '../components/PacketSimulator';

export default function Simulator() {
  return (
    <div style={{ padding: 24, maxWidth: 800, margin: '0 auto' }}>
      <h1 style={{ color: '#E6EDF3', marginTop: 0 }}>Packet Simulator</h1>
      <p style={{ color: '#8B949E', marginBottom: 24 }}>
        Test any URL, request body, or message to see how the 4-layer rule engine classifies it
        and which cipher would be applied.
      </p>
      <PacketSimulator />
    </div>
  );
}
