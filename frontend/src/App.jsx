import React, { useState, useEffect } from 'react';
import Navbar from './components/Navbar';
import MetricCards from './components/MetricCards';
import ScanModal from './components/ScanModal';
import FindingsTable from './components/FindingsTable';
import { scannerApi } from './services/api';

export default function App() {
  const [metrics, setMetrics] = useState(null);
  const [dbMode, setDbMode] = useState('MongoDB');
  const [scans, setScans] = useState([]);
  const [selectedScanId, setSelectedScanId] = useState(null);
  const [findings, setFindings] = useState([]);
  const [activeScanStatus, setActiveScanStatus] = useState(null);

  const loadData = async () => {
    try {
      const h = await scannerApi.getHealth();
      setDbMode(h.database ? h.database.mode : 'MongoDB');

      const m = await scannerApi.getMetrics();
      setMetrics(m);
      if (m.recent_scans) {
        setScans(m.recent_scans);
        if (m.recent_scans.length > 0 && !selectedScanId) {
          selectScan(m.recent_scans[0].scan_id);
        }
      }
    } catch (err) {
      console.error('Failed to load dashboard data:', err);
    }
  };

  const selectScan = async (scanId) => {
    setSelectedScanId(scanId);
    try {
      const res = await scannerApi.getScanResults(scanId);
      setFindings(res.findings || []);
    } catch (err) {
      console.error(err);
    }
  };

  const handleScanInitiated = (scanId) => {
    setSelectedScanId(scanId);
    const interval = setInterval(async () => {
      try {
        const s = await scannerApi.getScanStatus(scanId);
        setActiveScanStatus(s);
        if (s.status === 'COMPLETED' || s.status === 'FAILED') {
          clearInterval(interval);
          loadData();
          selectScan(scanId);
        }
      } catch (err) {
        clearInterval(interval);
      }
    }, 1500);
  };

  useEffect(() => {
    loadData();
  }, []);

  return (
    <div style={{ minHeight: '100vh', backgroundColor: '#0b0f19' }}>
      <Navbar dbMode={dbMode} onRefresh={loadData} />

      <div className="container-fluid px-4 py-4">
        {activeScanStatus && activeScanStatus.status !== 'COMPLETED' && (
          <div className="alert alert-info py-2 mb-4 d-flex justify-content-between align-items-center">
            <span>
              <i className="bi bi-gear-wide-connected me-2"></i>
              <b>Scan in Progress ({activeScanStatus.progress_percentage}%):</b>{' '}
              {activeScanStatus.current_engine || activeScanStatus.status}
            </span>
            <div className="spinner-border spinner-border-sm text-info" role="status"></div>
          </div>
        )}

        <ScanModal onScanInitiated={handleScanInitiated} />

        <MetricCards metrics={metrics} />

        <div className="row g-4 mb-4">
          <div className="col-md-5">
            <div className="card p-3 bg-dark border-secondary h-100">
              <h6 className="fw-bold mb-3 text-white">
                <i className="bi bi-clock-history text-info me-2"></i>Recent Scans
              </h6>
              <div className="list-group list-group-flush">
                {scans.length === 0 ? (
                  <div className="text-secondary small py-3">No scans run yet.</div>
                ) : (
                  scans.map((s) => (
                    <button
                      key={s.scan_id}
                      onClick={() => selectScan(s.scan_id)}
                      className={`list-group-item list-group-item-action bg-dark text-white border-secondary mb-2 rounded ${
                        selectedScanId === s.scan_id ? 'border-info border-2' : ''
                      }`}
                    >
                      <div className="d-flex justify-content-between align-items-center">
                        <span className="fw-bold">{s.project_name}</span>
                        <span
                          className={`badge bg-${
                            s.security_grade === 'A+' || s.security_grade === 'A'
                              ? 'success'
                              : s.security_grade === 'B'
                              ? 'info'
                              : s.security_grade === 'C'
                              ? 'warning'
                              : 'danger'
                          }`}
                        >
                          Grade {s.security_grade}
                        </span>
                      </div>
                      <div className="d-flex justify-content-between small text-secondary mt-1">
                        <span>{s.source_type}</span>
                        <span>{s.summary ? s.summary.total_findings : 0} issues</span>
                      </div>
                      <div className="mt-2 d-flex gap-2">
                        <a
                          href={`/api/v1/scans/${s.scan_id}/report/html`}
                          target="_blank"
                          rel="noreferrer"
                          className="btn btn-outline-info btn-sm py-0 px-2"
                        >
                          Audit
                        </a>
                        <a
                          href={`/api/v1/scans/${s.scan_id}/report/pdf`}
                          className="btn btn-outline-danger btn-sm py-0 px-2"
                        >
                          PDF
                        </a>
                        <a
                          href={`/api/v1/scans/${s.scan_id}/report/json`}
                          className="btn btn-outline-success btn-sm py-0 px-2"
                        >
                          JSON
                        </a>
                      </div>
                    </button>
                  ))
                )}
              </div>
            </div>
          </div>

          <div className="col-md-7">
            <FindingsTable findings={findings} selectedScanId={selectedScanId} />
          </div>
        </div>
      </div>
    </div>
  );
}
