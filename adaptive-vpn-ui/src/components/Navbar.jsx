// src/components/Navbar.jsx
import { Link, useLocation } from 'react-router-dom';
import { Shield } from 'lucide-react';

export default function Navbar() {
  const { pathname } = useLocation();

  const linkStyle = (path) => ({
    color: pathname === path ? '#00B4D8' : '#8B949E',
    textDecoration: 'none',
    fontWeight: pathname === path ? 'bold' : 'normal',
    padding: '4px 12px',
    borderRadius: 6,
    background: pathname === path ? '#00B4D822' : 'transparent',
    fontSize: 14,
  });

  return (
    <nav style={{
      background: '#161B22', borderBottom: '1px solid #30363D',
      padding: '12px 24px', display: 'flex', alignItems: 'center', gap: 24,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, color: '#00B4D8', fontWeight: 'bold', fontSize: 16 }}>
        <Shield size={20} />
        Adaptive VPN
      </div>
      <Link to="/" style={linkStyle('/')}>Dashboard</Link>
      <Link to="/simulator" style={linkStyle('/simulator')}>Simulator</Link>
    </nav>
  );
}
