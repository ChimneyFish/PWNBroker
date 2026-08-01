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

// ── UI behaviors (collapse / modal / dropdown / alert dismiss) ──────────
// Replaces what Bootstrap's JS bundle used to drive via data-bs-* attributes.
// Same shape, no "bs" prefix: data-toggle / data-target / data-dismiss.
(function () {
  function targetOf(el) {
    const sel = el.getAttribute('data-target') || el.getAttribute('href');
    return sel ? document.querySelector(sel) : null;
  }

  document.addEventListener('click', (e) => {
    // Collapse (sidebar nav groups)
    const collapseToggle = e.target.closest('[data-toggle="collapse"]');
    if (collapseToggle) {
      e.preventDefault();
      const panel = targetOf(collapseToggle);
      if (panel) {
        const opening = !panel.classList.contains('show');
        panel.classList.toggle('show', opening);
        collapseToggle.classList.toggle('collapsed', !opening);
        collapseToggle.setAttribute('aria-expanded', String(opening));
      }
      return;
    }

    // Tabs
    const tabToggle = e.target.closest('[data-toggle="tab"]');
    if (tabToggle) {
      e.preventDefault();
      const pane = targetOf(tabToggle);
      const tabGroup = tabToggle.closest('.nav-tabs') || tabToggle.parentElement;
      const paneGroup = pane?.parentElement;
      tabGroup?.querySelectorAll('.nav-link').forEach((el) => el.classList.remove('active'));
      paneGroup?.querySelectorAll('.tab-pane').forEach((el) => el.classList.remove('active', 'show'));
      tabToggle.classList.add('active');
      pane?.classList.add('active', 'show');
      return;
    }

    // Modal open
    const modalToggle = e.target.closest('[data-toggle="modal"]');
    if (modalToggle) {
      e.preventDefault();
      const modal = targetOf(modalToggle);
      if (modal) openModal(modal);
      return;
    }

    // Modal dismiss (close button or backdrop click)
    const modalDismiss = e.target.closest('[data-dismiss="modal"]');
    if (modalDismiss) {
      e.preventDefault();
      closeModal(modalDismiss.closest('.modal'));
      return;
    }
    if (e.target.classList.contains('modal') && e.target.classList.contains('show')) {
      closeModal(e.target);
      return;
    }

    // Alert dismiss
    const alertDismiss = e.target.closest('[data-dismiss="alert"]');
    if (alertDismiss) {
      const alertEl = alertDismiss.closest('.alert');
      if (alertEl) alertEl.remove();
      return;
    }

    // Dropdown toggle
    const dropdownToggle = e.target.closest('[data-toggle="dropdown"]');
    if (dropdownToggle) {
      e.preventDefault();
      const menu = dropdownToggle.nextElementSibling?.classList.contains('dropdown-menu')
        ? dropdownToggle.nextElementSibling
        : dropdownToggle.parentElement.querySelector('.dropdown-menu');
      document.querySelectorAll('.dropdown-menu.show').forEach((m) => { if (m !== menu) m.classList.remove('show'); });
      menu?.classList.toggle('show');
      return;
    }
    if (!e.target.closest('.dropdown-menu')) {
      document.querySelectorAll('.dropdown-menu.show').forEach((m) => m.classList.remove('show'));
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal.show').forEach(closeModal);
    }
  });

  function openModal(modal) {
    modal.classList.add('show');
    document.body.style.overflow = 'hidden';
  }
  function closeModal(modal) {
    if (!modal) return;
    modal.classList.remove('show');
    document.body.style.overflow = '';
  }
})();

