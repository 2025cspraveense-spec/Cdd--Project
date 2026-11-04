import React from 'react';

export default function Navbar({ dbMode, onRefresh }) {
  return (
    <nav className="navbar navbar-dark border-bottom border-secondary px-4 py-3" style={{ backgroundColor: '#0f172a' }}>
      <div className="d-flex align-items-center gap-3">
        <i className="bi bi-shield-lock-fill text-info fs-3"></i>
        <div>
          <h5 className="mb-0 fw-bold text-white">Secret Leak Guard</h5>
          <small className="text-secondary">Universal Source Code Security Scanner (Gitleaks, Semgrep, Trivy, OSV)</small>
        </div>
      </div>
      <div className="d-flex align-items-center gap-3">
        <span className="badge bg-success py-2 px-3">
          <i className="bi bi-database-check me-1"></i> {dbMode || 'MongoDB'}
        </span>
        <button className="btn btn-outline-info btn-sm" onClick={onRefresh}>
          <i className="bi bi-arrow-clockwise"></i> Refresh
        </button>
      </div>
    </nav>
  );
}
