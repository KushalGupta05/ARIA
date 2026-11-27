import { useCallback, useEffect, useRef, useState } from 'react';
import { fetchAlerts } from '../api/ariaClient.js';

const POLL_MS = Number(import.meta.env.VITE_POLL_MS) || 5000;

// Polls the ARIA API and exposes live alert state to pages.
export function useLiveAlerts() {
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [lastUpdated, setLastUpdated] = useState(null);
  const alive = useRef(true);

  const refresh = useCallback(async () => {
    try {
      const data = await fetchAlerts();
      if (!alive.current) return;
      setAlerts(data);
      setError(null);
      setLastUpdated(new Date());
    } catch (e) {
      if (alive.current) setError(e.message || String(e));
    } finally {
      if (alive.current) setLoading(false);
    }
  }, []);

  useEffect(() => {
    alive.current = true;
    refresh();
    const id = setInterval(refresh, POLL_MS);
    return () => { alive.current = false; clearInterval(id); };
  }, [refresh]);

  return { alerts, loading, error, lastUpdated, refresh, setAlerts };
}
