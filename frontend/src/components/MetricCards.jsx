import React from 'react';

export default function MetricCards({ metrics }) {
  const m = metrics || {};
  const sev = m.severity_distribution || {};
  const cat = m.category_distribution || {};

  return (
    <div className="row g-3 mb-4">
      <div className="col-md-2">
        <div className="card p-3 text-center bg-dark border-secondary">
          <small className="text-secondary text-uppercase fw-semibold">Projects Scanned</small>
          <div className="fs-2 fw-bold text-white">{m.total_projects || 0}</div>
        </div>
      </div>
      <div className="col-md-2">
        <div className="card p-3 text-center bg-dark border-secondary">
          <small className="text-secondary text-uppercase fw-semibold">Total Findings</small>
          <div className="fs-2 fw-bold text-info">{m.total_findings || 0}</div>
        </div>
      </div>
      <div className="col-md-2">
        <div className="card p-3 text-center bg-dark border-secondary">
          <small className="text-secondary text-uppercase fw-semibold">Critical Issues</small>
          <div className="fs-2 fw-bold text-danger">{sev.critical || 0}</div>
        </div>
      </div>
      <div className="col-md-2">
        <div className="card p-3 text-center bg-dark border-secondary">
          <small className="text-secondary text-uppercase fw-semibold">High Severity</small>
          <div className="fs-2 fw-bold text-warning">{sev.high || 0}</div>
        </div>
      </div>
      <div className="col-md-2">
        <div className="card p-3 text-center bg-dark border-secondary">
          <small className="text-secondary text-uppercase fw-semibold">Exposed Secrets</small>
          <div className="fs-2 fw-bold" style={{ color: '#f59e0b' }}>{cat.secrets || 0}</div>
        </div>
      </div>
      <div className="col-md-2">
        <div className="card p-3 text-center bg-dark border-secondary">
          <small className="text-secondary text-uppercase fw-semibold">Avg Risk Score</small>
          <div className="fs-2 fw-bold text-white">{m.average_risk_score || 0}/100</div>
        </div>
      </div>
    </div>
  );
}
