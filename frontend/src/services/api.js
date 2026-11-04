const API_BASE = '/api/v1';

export const scannerApi = {
  getHealth: async () => {
    const res = await fetch(`${API_BASE}/health`);
    return res.json();
  },

  getMetrics: async () => {
    const res = await fetch(`${API_BASE}/dashboard/metrics`);
    return res.json();
  },

  getProjects: async () => {
    const res = await fetch(`${API_BASE}/projects`);
    return res.json();
  },

  getScans: async () => {
    const res = await fetch(`${API_BASE}/scans`);
    return res.json();
  },

  getScanStatus: async (scanId) => {
    const res = await fetch(`${API_BASE}/scans/${scanId}/status`);
    return res.json();
  },

  getScanResults: async (scanId, filters = {}) => {
    const params = new URLSearchParams(filters);
    const res = await fetch(`${API_BASE}/scans/${scanId}/results?${params.toString()}`);
    return res.json();
  },

  submitLocalScan: async (path, projectName, scanHistory = false) => {
    const res = await fetch(`${API_BASE}/scans/local`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ path, project_name: projectName, scan_history: scanHistory }),
    });
    return res.json();
  },

  submitUploadScan: async (file, projectName, scanHistory = false) => {
    const formData = new FormData();
    formData.append('file', file);
    if (projectName) formData.append('project_name', projectName);
    formData.append('scan_history', scanHistory ? 'true' : 'false');

    const res = await fetch(`${API_BASE}/scans/upload`, {
      method: 'POST',
      body: formData,
    });
    return res.json();
  },

  submitGithubScan: async (repoUrl, branch, projectName, scanHistory = false) => {
    const res = await fetch(`${API_BASE}/scans/github`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        repo_url: repoUrl,
        branch,
        project_name: projectName,
        scan_history: scanHistory,
      }),
    });
    return res.json();
  },

  submitDockerScan: async (dockerfileContent, projectName) => {
    const res = await fetch(`${API_BASE}/scans/docker`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ dockerfile_content: dockerfileContent, project_name: projectName }),
    });
    return res.json();
  },
};
