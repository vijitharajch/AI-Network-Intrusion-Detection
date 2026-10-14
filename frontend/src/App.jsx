
import React, { useEffect, useRef, useState } from 'react';

import {
  getStats,
  getAlerts,
  predictCSV
} from './services/api';

function Stat({ label, value, kind = '' }) {
  return (
    <div className={`stat ${kind}`}>
      <span>{label}</span>
      <strong>{value ?? 0}</strong>
    </div>
  );
}

function App() {
  const [stats, setStats] = useState({});
  const [alerts, setAlerts] = useState([]);
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [refreshError, setRefreshError] = useState('');

  const loadingRef = useRef(false);
  const refreshingRef = useRef(false);

  const load = async () => {
    if (loadingRef.current || refreshingRef.current) return;

    refreshingRef.current = true;

    try {
      const [nextStats, nextAlerts] = await Promise.all([
        getStats(),
        getAlerts()
      ]);

      setStats(nextStats);
      setAlerts(Array.isArray(nextAlerts) ? nextAlerts : []);
      setRefreshError('');
    } catch (e) {
      console.error('Dashboard refresh failed:', e);
      setRefreshError(
        'Could not refresh dashboard data. Check the backend connection.'
      );
    } finally {
      refreshingRef.current = false;
    }
  };

  useEffect(() => {
    load();

    const id = setInterval(load, 10000);

    return () => clearInterval(id);
  }, []);

  const upload = async () => {
    if (!file || loadingRef.current) return;

    loadingRef.current = true;
    setLoading(true);
    setError('');
    setResult(null);

    try {
      const data = await predictCSV(file);

      setResult(data);

      // Refresh alert statistics after CSV analysis.
      await load();
    } catch (e) {
      setError(
        e.message || 'CSV analysis failed. Check the backend.'
      );
      console.error('CSV upload failed:', e);
    } finally {
      loadingRef.current = false;
      setLoading(false);
    }
  };

  return (
    <div className="app">
      <header>
        <div>
          <p className="eyebrow">AI-POWERED NIDS</p>

          <h1>Security Monitoring Center</h1>

          <p className="sub">
            Network-flow intrusion detection, anomaly analysis and
            risk prioritization.
          </p>
        </div>

        <div className="status">
          <i />
          API MONITORING
        </div>
      </header>

      <main>
        {/* Security alert counters */}
        <section className="stats">
          <Stat
            label="Total Alerts"
            value={stats.alerts}
          />

          <Stat
            label="Critical"
            value={stats.critical}
            kind="critical"
          />

          <Stat
            label="High Risk"
            value={stats.high}
            kind="high"
          />

          <Stat
            label="Medium Risk"
            value={stats.medium}
            kind="medium"
          />
        </section>

        {/* CSV detection and attack distribution */}
        <section className="grid">
          <div className="panel upload">
            <h2>Analyze Network Traffic</h2>

            <p>
              Upload a CICIDS2017-compatible CSV flow file for
              batch detection.
            </p>

            <input
              type="file"
              accept=".csv"
              onChange={(e) => {
                setFile(e.target.files?.[0] || null);
                setError('');
                setResult(null);
              }}
            />

            <button
              onClick={upload}
              disabled={!file || loading}
            >
              {loading ? 'Analyzing...' : 'Run Detection'}
            </button>

            {loading && (
              <p>
                Processing the CSV. Large files may take time.
              </p>
            )}

            {error && (
              <p
                role="alert"
                style={{ color: '#ff6b6b' }}
              >
                {error}
              </p>
            )}

            {result && (
              <div className="result">
                <b>{result.total ?? 0}</b> flows analyzed ·{' '}
                <b>{result.suspicious ?? 0}</b> suspicious
              </div>
            )}
          </div>

          <div className="panel">
            <h2>Attack Distribution</h2>

            {Object.entries(stats.attack_types || {}).length === 0 ? (
              <p className="muted">No alerts yet.</p>
            ) : (
              Object.entries(stats.attack_types).map(
                ([name, count]) => {
                  const maximum = Math.max(
                    1,
                    ...Object.values(stats.attack_types)
                  );

                  return (
                    <div className="bar" key={name}>
                      <span>{name}</span>

                      <div>
                        <i
                          style={{
                            width: `${Math.min(
                              100,
                              (count / maximum) * 100
                            )}%`
                          }}
                        />
                      </div>

                      <b>{count}</b>
                    </div>
                  );
                }
              )
            )}
          </div>
        </section>

        {/* Backend refresh errors */}
        {refreshError && (
          <p
            role="alert"
            style={{ color: '#ff6b6b' }}
          >
            {refreshError}
          </p>
        )}

        {/* Recent security alerts */}
        <section className="panel">
          <div className="panelhead">
            <h2>Recent Security Alerts</h2>

            <button
              className="ghost"
              onClick={load}
            >
              Refresh
            </button>
          </div>

          <div className="tablewrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Prediction</th>
                  <th>Confidence</th>
                  <th>Anomaly</th>
                  <th>Risk</th>
                  <th>Source</th>
                  <th>Destination</th>
                </tr>
              </thead>

              <tbody>
                {alerts.length === 0 ? (
                  <tr>
                    <td
                      colSpan="7"
                      className="empty"
                    >
                      No alerts recorded.
                    </td>
                  </tr>
                ) : (
                  alerts.map((a) => (
                    <tr key={a.id}>
                      <td>
                        {new Date(
                          a.timestamp
                        ).toLocaleString()}
                      </td>

                      <td>{a.prediction}</td>

                      <td>
                        {(Number(a.confidence) * 100).toFixed(1)}%
                      </td>

                      <td>
                        {a.anomaly ? 'YES' : 'NO'}
                      </td>

                      <td>
                        <span
                          className={`badge ${
                            (a.risk || '').toLowerCase()
                          }`}
                        >
                          {a.risk}
                        </span>
                      </td>

                      <td>{a.source_ip}</td>

                      <td>{a.destination_ip}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;
