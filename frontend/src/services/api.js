
const API = import.meta.env.VITE_API_URL || "http://127.0.0.1:8000";

async function request(url, options = {}) {
  const response = await fetch(url, options);

  if (!response.ok) {
    const message = await response.text();
    throw new Error(`API error ${response.status}: ${message}`);
  }

  return response.json();
}

export function getStats() {
  return request(`${API}/api/stats`);
}

export function getAlerts() {
  return request(`${API}/api/alerts`);
}

export function getLiveFlows() {
  return request(`${API}/api/live-flows`);
}

export function predict(features, source_ip, destination_ip) {
  return request(`${API}/api/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ features, source_ip, destination_ip }),
  });
}

export function predictCSV(file) {
  const fd = new FormData();
  fd.append("file", file);

  return request(`${API}/api/predict/csv`, {
    method: "POST",
    body: fd,
  });
}
