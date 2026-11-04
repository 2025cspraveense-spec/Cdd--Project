import React, { useState } from 'react';

export default function FindingsTable({ findings, selectedScanId }) {
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  const list = findings || [];
  const filtered = list.filter((f) => {
    const matchSev = filterSeverity === 'ALL' || f.severity === filterSeverity;
    const q = searchTerm.toLowerCase();
    const matchSearch =
      !q ||
      f.title.toLowerCase().includes(q) ||
      f.file_path.toLowerCase().includes(q) ||
      (f.description && f.description.toLowerCase().includes(q));
    return matchSev && matchSearch;
  });

  return (
    <div className="card p-3 bg-dark border-secondary">
      <div className="d-flex justify-content-between align-items-center mb-3">
        <h6 className="fw-bold mb-0 text-white">
          <i className="bi bi-shield-exclamation text-warning me-2"></i>
          Security Findings ({filtered.length})
        </h6>
        <div className="d-flex gap-2">
          <input
            type="text"
            className="form-control form-control-sm bg-dark text-white border-secondary"
            placeholder="Search findings or files..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
          />
          <select
            className="form-select form-select-sm bg-dark text-white border-secondary"
            value={filterSeverity}
            onChange={(e) => setFilterSeverity(e.target.value)}
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>
        </div>
      </div>

      <div className="table-responsive">
        <table className="table table-dark table-hover align-middle mb-0">
          <thead>
            <tr>
              <th style={{ width: '110px' }}>Severity</th>
              <th>Vulnerability Title</th>
              <th>Location</th>
              <th>Engine</th>
              <th>CWE</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan="5" className="text-center text-muted py-4">
                  No findings to display.
                </td>
              </tr>
            ) : (
              filtered.map((f, i) => {
                const sevColor =
                  f.severity === 'CRITICAL'
                    ? 'danger'
                    : f.severity === 'HIGH'
                    ? 'warning'
                    : f.severity === 'MEDIUM'
                    ? 'info'
                    : 'secondary';
                return (
                  <tr key={f.finding_id || i}>
                    <td>
                      <span className={`badge bg-${sevColor}`}>{f.severity}</span>
                    </td>
                    <td>
                      <div className="fw-bold text-white">{f.title}</div>
                      <div className="text-secondary small">{f.description}</div>
                      {f.evidence_redacted && (
                        <pre
                          className="mt-1 mb-0 p-1 rounded small"
                          style={{
                            backgroundColor: '#090d16',
                            color: '#38bdf8',
                            border: '1px solid #1f2937',
                            whiteSpace: 'pre-wrap',
                            wordBreak: 'break-all',
                          }}
                        >
                          {f.evidence_redacted}
                        </pre>
                      )}
                      {f.recommended_remediation && (
                        <div className="small text-info mt-1">
                          <b>Remediation:</b> {f.recommended_remediation}
                        </div>
                      )}
                    </td>
                    <td>
                      <code className="text-info">{f.file_path}:{f.line_number || 'N/A'}</code>
                    </td>
                    <td>
                      <span className="badge bg-secondary">{f.engine}</span>
                    </td>
                    <td>
                      <small className="text-muted">{f.cwe || 'N/A'}</small>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
