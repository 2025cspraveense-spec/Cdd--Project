import React, { useState } from 'react';
import { scannerApi } from '../services/api';

export default function ScanModal({ onScanInitiated }) {
  const [activeTab, setActiveTab] = useState('local');
  const [localPath, setLocalPath] = useState('');
  const [localProj, setLocalProj] = useState('');
  const [uploadFile, setUploadFile] = useState(null);
  const [uploadProj, setUploadProj] = useState('');
  const [githubUrl, setGithubUrl] = useState('');
  const [githubBranch, setGithubBranch] = useState('');
  const [dockerContent, setDockerContent] = useState('');
  const [scanHistory, setScanHistory] = useState(false);
  const [loading, setLoading] = useState(false);
  const [statusMsg, setStatusMsg] = useState(null);

  const handleLocalSubmit = async (e) => {
    e.preventDefault();
    if (!localPath) return alert('Enter local folder path');
    setLoading(true);
    try {
      const res = await scannerApi.submitLocalScan(localPath, localProj, scanHistory);
      if (res.scan_id) {
        setStatusMsg({ type: 'info', text: `Scan queued: ${res.scan_id}` });
        onScanInitiated(res.scan_id);
      } else {
        setStatusMsg({ type: 'danger', text: res.error || 'Failed to submit scan' });
      }
    } catch (err) {
      setStatusMsg({ type: 'danger', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleUploadSubmit = async (e) => {
    e.preventDefault();
    if (!uploadFile) return alert('Please select a file to upload');
    setLoading(true);
    try {
      const res = await scannerApi.submitUploadScan(uploadFile, uploadProj, scanHistory);
      if (res.scan_id) {
        setStatusMsg({ type: 'info', text: `Upload scan queued: ${res.scan_id}` });
        onScanInitiated(res.scan_id);
      } else {
        setStatusMsg({ type: 'danger', text: res.error || 'Upload failed' });
      }
    } catch (err) {
      setStatusMsg({ type: 'danger', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleGithubSubmit = async (e) => {
    e.preventDefault();
    if (!githubUrl) return alert('Enter repository URL');
    setLoading(true);
    try {
      const res = await scannerApi.submitGithubScan(githubUrl, githubBranch, '', scanHistory);
      if (res.scan_id) {
        setStatusMsg({ type: 'info', text: `Repository clone queued: ${res.scan_id}` });
        onScanInitiated(res.scan_id);
      } else {
        setStatusMsg({ type: 'danger', text: res.error || 'Clone failed' });
      }
    } catch (err) {
      setStatusMsg({ type: 'danger', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  const handleDockerSubmit = async (e) => {
    e.preventDefault();
    if (!dockerContent) return alert('Paste Dockerfile or compose content');
    setLoading(true);
    try {
      const res = await scannerApi.submitDockerScan(dockerContent, 'Dockerfile-Audit');
      if (res.scan_id) {
        setStatusMsg({ type: 'info', text: `Docker scan queued: ${res.scan_id}` });
        onScanInitiated(res.scan_id);
      } else {
        setStatusMsg({ type: 'danger', text: res.error || 'Scan failed' });
      }
    } catch (err) {
      setStatusMsg({ type: 'danger', text: err.message });
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="card p-4 mb-4 bg-dark border-secondary shadow-sm">
      <h6 className="fw-bold mb-3 text-info"><i className="bi bi-play-circle"></i> Launch New Security Scan</h6>
      <ul className="nav nav-tabs mb-3 border-secondary">
        <li className="nav-item">
          <button className={`nav-link ${activeTab === 'local' ? 'active text-info fw-bold' : 'text-secondary'}`} onClick={() => setActiveTab('local')}>Local Folder</button>
        </li>
        <li className="nav-item">
          <button className={`nav-link ${activeTab === 'upload' ? 'active text-info fw-bold' : 'text-secondary'}`} onClick={() => setActiveTab('upload')}>Upload ZIP / Code</button>
        </li>
        <li className="nav-item">
          <button className={`nav-link ${activeTab === 'github' ? 'active text-info fw-bold' : 'text-secondary'}`} onClick={() => setActiveTab('github')}>GitHub Repo</button>
        </li>
        <li className="nav-item">
          <button className={`nav-link ${activeTab === 'docker' ? 'active text-info fw-bold' : 'text-secondary'}`} onClick={() => setActiveTab('docker')}>Dockerfile / Compose</button>
        </li>
      </ul>

      {activeTab === 'local' && (
        <form onSubmit={handleLocalSubmit} className="row g-2 align-items-center">
          <div className="col-md-5">
            <input type="text" className="form-control bg-dark text-white border-secondary" placeholder="Local directory path (e.g. E:\Cdd\secret-leak-guard\bad-example)" value={localPath} onChange={e => setLocalPath(e.target.value)} />
          </div>
          <div className="col-md-3">
            <input type="text" className="form-control bg-dark text-white border-secondary" placeholder="Project Name" value={localProj} onChange={e => setLocalProj(e.target.value)} />
          </div>
          <div className="col-md-2 form-check ps-4">
            <input type="checkbox" className="form-check-input" id="histCheck" checked={scanHistory} onChange={e => setScanHistory(e.target.checked)} />
            <label className="form-check-label text-secondary small" htmlFor="histCheck">Scan Git History</label>
          </div>
          <div className="col-md-2">
            <button type="submit" disabled={loading} className="btn btn-info w-100 fw-bold">
              {loading ? 'Submitting...' : 'Scan Folder'}
            </button>
          </div>
        </form>
      )}

      {activeTab === 'upload' && (
        <form onSubmit={handleUploadSubmit} className="row g-2 align-items-center">
          <div className="col-md-5">
            <input type="file" className="form-control bg-dark text-white border-secondary" onChange={e => setUploadFile(e.target.files[0])} />
          </div>
          <div className="col-md-4">
            <input type="text" className="form-control bg-dark text-white border-secondary" placeholder="Project Name" value={uploadProj} onChange={e => setUploadProj(e.target.value)} />
          </div>
          <div className="col-md-3">
            <button type="submit" disabled={loading} className="btn btn-info w-100 fw-bold">
              {loading ? 'Uploading...' : 'Upload & Scan'}
            </button>
          </div>
        </form>
      )}

      {activeTab === 'github' && (
        <form onSubmit={handleGithubSubmit} className="row g-2 align-items-center">
          <div className="col-md-5">
            <input type="url" className="form-control bg-dark text-white border-secondary" placeholder="https://github.com/org/repo" value={githubUrl} onChange={e => setGithubUrl(e.target.value)} />
          </div>
          <div className="col-md-3">
            <input type="text" className="form-control bg-dark text-white border-secondary" placeholder="Branch (default main)" value={githubBranch} onChange={e => setGithubBranch(e.target.value)} />
          </div>
          <div className="col-md-2 form-check ps-4">
            <input type="checkbox" className="form-check-input" id="gitHistCheck" checked={scanHistory} onChange={e => setScanHistory(e.target.checked)} />
            <label className="form-check-label text-secondary small" htmlFor="gitHistCheck">Scan History</label>
          </div>
          <div className="col-md-2">
            <button type="submit" disabled={loading} className="btn btn-info w-100 fw-bold">
              {loading ? 'Cloning...' : 'Clone & Scan'}
            </button>
          </div>
        </form>
      )}

      {activeTab === 'docker' && (
        <form onSubmit={handleDockerSubmit}>
          <textarea rows="4" className="form-control bg-dark text-white border-secondary mb-2" placeholder="Paste Dockerfile or docker-compose.yml content..." value={dockerContent} onChange={e => setDockerContent(e.target.value)}></textarea>
          <button type="submit" disabled={loading} className="btn btn-info fw-bold">
            {loading ? 'Scanning...' : 'Scan Dockerfile'}
          </button>
        </form>
      )}

      {statusMsg && (
        <div className={`alert alert-${statusMsg.type} mt-3 mb-0 py-2 small`}>
          {statusMsg.text}
        </div>
      )}
    </div>
  );
}
