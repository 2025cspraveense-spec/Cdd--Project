import React from 'react';

export default function Navbar({ dbMode, onRefresh }) {
  return (
    <nav className="navbar navbar-dark border-bottom border-secondary px-4 py-3" style={{ backgroundColor: '#0f172a' }}>
      <div className="d-flex align-items-center gap-3">
        <i className="bi bi-shield-lock-fill text-info fs-3"></i>
        <div>
          <h5 className="mb-0 fw-bold text-white">Secret Leak Guard</h5>
          <small className="text-secondary">Universal DevSecOps Gateway (Nginx Unified Portal)</small>
        </div>
      </div>
      <div className="d-flex align-items-center gap-2">
        <div className="btn-group me-2" role="group" aria-label="Unified Service Switcher">
          <a href="/" className="btn btn-outline-info btn-sm active" title="Universal Security Scanner">
            <i className="bi bi-shield-check me-1"></i> Scanner
          </a>
          <a href="/app/" target="_blank" rel="noreferrer" className="btn btn-outline-secondary btn-sm" title="Runtime Secured Demo App">
            <i className="bi bi-lock-fill me-1"></i> Secured App
          </a>
          <a href="/vault/" target="_blank" rel="noreferrer" className="btn btn-outline-secondary btn-sm" title="HashiCorp Vault UI">
            <i className="bi bi-safe me-1"></i> Vault
          </a>
          <a href="/nginx-health" target="_blank" rel="noreferrer" className="btn btn-outline-secondary btn-sm" title="Nginx Gateway Health Status">
            <i className="bi bi-diagram-3 me-1"></i> Gateway
          </a>
        </div>
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
