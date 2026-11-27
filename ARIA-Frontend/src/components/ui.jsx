import React, { useEffect, useRef, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { Bell, ShieldCheck, Sun, Moon, ChevronDown, LogOut, Settings, Clock3, CircleHelp } from 'lucide-react';
import { useTheme } from '../context/ThemeContext.jsx';

export function ThemeToggle({ fixed = false }) {
  const { theme, toggle } = useTheme();
  return (
    <button
      className={`icon-button theme-toggle ${fixed ? 'theme-fixed' : ''}`}
      onClick={toggle}
      aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
      title={`Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`}
    >
      {theme === 'dark' ? <Sun size={15} /> : <Moon size={15} />}
    </button>
  );
}

export function LiveClock() {
  const [time, setTime] = useState(() => new Date());
  useEffect(() => {
    const id = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(id);
  }, []);
  return (
    <div className="clock">
      <Clock3 size={14} />
      <span>{time.toLocaleTimeString('en-GB', { hour12: false, timeZone: 'UTC' })} UTC</span>
    </div>
  );
}

function UserMenu() {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  const nav = useNavigate();
  useEffect(() => {
    const listener = e => {
      if (e.key === 'Escape') setOpen(false);
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    document.addEventListener('mousedown', listener);
    document.addEventListener('keydown', listener);
    return () => {
      document.removeEventListener('mousedown', listener);
      document.removeEventListener('keydown', listener);
    };
  }, []);

  return (
    <div ref={ref} className="user-menu" style={{ position: 'relative' }}>
      <button className="avatar-button" aria-label="Open user menu" aria-expanded={open} onClick={() => setOpen(v => !v)}>
        <span>AN</span>
        <ChevronDown size={14} />
      </button>
      {open && (
        <div className="menu-popover" style={{ position: 'absolute', right: 0, top: 'calc(100% + 4px)', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 4, padding: 4, zIndex: 100, minWidth: 140, boxShadow: '0 4px 12px rgba(0,0,0,0.5)' }}>
          <button className="btn" style={{ width: '100%', textAlign: 'left', border: 'none', display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', fontSize: '12px' }} onClick={() => { setOpen(false); nav('/settings'); }}>
            <Settings size={14} />Settings
          </button>
          <div className="menu-divider" style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />
          <button className="btn" style={{ width: '100%', textAlign: 'left', border: 'none', display: 'flex', alignItems: 'center', gap: 8, padding: '6px 10px', fontSize: '12px', color: 'var(--red)' }} onClick={() => nav('/login')}>
            <LogOut size={14} />Exit console
          </button>
        </div>
      )}
    </div>
  );
}

export function TopNav({ triage = false }) {
  const loc = useLocation();
  const nav = useNavigate();

  const tabs = [
    ['Dashboard', '/dashboard'],
    ['Alerts', '/triage'],
    ['Threat Intel', '/threat-intel'],
    ['Analytics', '/analytics'],
    ['Settings', '/settings'],
  ];

  const isTabActive = (path) => {
    const current = loc.pathname;
    if (path === '/dashboard') return current === '/' || current === '/dashboard';
    if (path === '/triage') return current.startsWith('/triage');
    return current.startsWith(path);
  };

  return (
    <header className="top-nav">
      <button className="brand" onClick={() => nav('/dashboard')}>
        <ShieldCheck size={18} />
        <span>ARIA</span>
      </button>

      {triage && (
        <button className="back-link" onClick={() => nav('/dashboard')} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer', fontSize: '12px', marginLeft: 8 }}>
          ‹ <span>Back to Dashboard</span>
        </button>
      )}

      <nav className="nav-tabs">
        {tabs.map(([label, path]) => {
          const active = isTabActive(path);
          return (
            <button
              key={label}
              className={`nav-tab ${active ? 'active' : ''}`}
              onClick={() => nav(path)}
            >
              {label}
            </button>
          );
        })}
      </nav>

      <div className="nav-utilities">
        <LiveClock />
        <ThemeToggle />
        <button className="icon-button notification" aria-label="Notifications" style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer', padding: 4 }}>
          <Bell size={15} />
        </button>
        <UserMenu />
      </div>
    </header>
  );
}

export function SeverityBadge({ value }) {
  return <span className={`severity-badge ${(value || 'low').toLowerCase()}`}>{value}</span>;
}

export function Button({ children, onClick, tone = 'primary', className = '', ...props }) {
  return <button className={`button ${tone} ${className}`} onClick={onClick} {...props}>{children}</button>;
}

export function SectionTitle({ children, aside }) {
  return (
    <div className="section-title">
      <h2>{children}</h2>
      {aside && <span>{aside}</span>}
    </div>
  );
}

export function FilterPills({ options, value, onChange }) {
  return (
    <div className="filter-pills" role="group">
      {options.map(o => (
        <button key={o} aria-pressed={o === value} className={o === value ? 'selected' : ''} onClick={() => onChange(o)}>
          {o}
        </button>
      ))}
    </div>
  );
}

export function EmptyState() {
  return (
    <div className="empty-state">
      <CircleHelp size={26} />
      <h2>Select an alert to triage</h2>
      <p>Choose an alert from the queue to begin analysis.</p>
    </div>
  );
}

export function AuthLayout({ children }) {
  return (
    <main className="auth-layout">
      <ThemeToggle fixed />
      <div className="auth-card">{children}</div>
      <div className="auth-foot">Local analyst console</div>
    </main>
  );
}
