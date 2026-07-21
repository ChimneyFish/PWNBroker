// Attach the CSRF token to every same-origin state-changing fetch() call, so
// individual call sites across the app don't each need to set the header.
(function () {
  const token = document.querySelector('meta[name="csrf-token"]')?.content;
  const mutating = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
  const originalFetch = window.fetch;

  window.fetch = function (input, init = {}) {
    const url = typeof input === 'string' ? input : input.url;
    const method = (init.method || (input instanceof Request ? input.method : 'GET') || 'GET').toUpperCase();
    const isSameOrigin = url.startsWith('/') || url.startsWith(window.location.origin);

    if (token && isSameOrigin && mutating.has(method)) {
      init = { ...init };
      init.headers = new Headers(init.headers || (input instanceof Request ? input.headers : undefined));
      if (!init.headers.has('X-CSRFToken')) {
        init.headers.set('X-CSRFToken', token);
      }
    }
    return originalFetch(input, init);
  };
})();

// Auto-refresh scan status on the scan view page
function pollScanStatus(scanId) {
  const statusEl = document.getElementById('scan-status-badge');
  const statsEl = document.getElementById('scan-stats');
  if (!statusEl) return;

  const interval = setInterval(async () => {
    try {
      const res = await fetch(`/api/scans/${scanId}/status`);
      const data = await res.json();

      statusEl.className = `badge-status status-${data.status}`;
      statusEl.textContent = data.status.toUpperCase();

      if (statsEl) {
        statsEl.querySelector('[data-stat="vulns"]').textContent = data.vuln_count;
        statsEl.querySelector('[data-stat="critical"]').textContent = data.critical_count;
      }

      if (data.status === 'done' || data.status === 'failed') {
        clearInterval(interval);
        setTimeout(() => location.reload(), 800);
      }
    } catch (e) { /* ignore */ }
  }, 2500);
}

// Toast helper
function showToast(msg, type = 'success') {
  const toastContainer = document.getElementById('toast-container') || (() => {
    const c = document.createElement('div');
    c.id = 'toast-container';
    c.style.cssText = 'position:fixed;bottom:20px;right:20px;z-index:9999';
    document.body.appendChild(c);
    return c;
  })();

  const el = document.createElement('div');
  el.className = `alert alert-${type} shadow mb-2`;
  el.style.cssText = 'min-width:240px;animation:fadeIn 0.2s';
  el.textContent = msg;
  toastContainer.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

// Toggle scheduled scan active state
document.addEventListener('click', async (e) => {
  const btn = e.target.closest('[data-toggle-sched]');
  if (!btn) return;
  const id = btn.dataset.toggleSched;
  const res = await fetch(`/scans/schedule/${id}/toggle`, { method: 'POST' });
  const data = await res.json();
  btn.textContent = data.active ? 'Active' : 'Paused';
  btn.className = data.active
    ? 'badge badge-status status-done cursor-pointer'
    : 'badge badge-status status-pending cursor-pointer';
  showToast(data.active ? 'Schedule activated' : 'Schedule paused');
});

// Confirm before delete
document.addEventListener('submit', (e) => {
  const form = e.target.closest('form[data-confirm]');
  if (!form) return;
  if (!confirm(form.dataset.confirm || 'Are you sure?')) {
    e.preventDefault();
  }
});

