/**
 * HexBrain UI Interactions
 * Handles search overlay, panel toggle, lens switching, and keyboard shortcuts.
 */

(function () {
  'use strict';

  // --- DOM references ---
  const findOverlay = document.getElementById('findOverlay');
  const findBtn = document.getElementById('findBtn');
  const escBtn = document.getElementById('escBtn');
  const searchInput = document.getElementById('searchInput');
  const findList = document.getElementById('findList');
  const sidePanel = document.getElementById('sidePanel');
  const searchBtn = document.getElementById('searchBtn');
  const exploreBtn = document.getElementById('exploreBtn');
  const hero = document.querySelector('.hero');
  const stats = document.querySelector('.stats');

  // --- Search data (mock) ---
  const searchData = [
    { type: 'class', label: 'Cross-site Scripting (XSS)', sub: '4,127 reports · 87 weaknesses' },
    { type: 'class', label: 'Improper Access Control', sub: '2,156 reports · 34 weaknesses' },
    { type: 'class', label: 'Information Disclosure', sub: '1,893 reports · 28 weaknesses' },
    { type: 'class', label: 'Server-Side Request Forgery (SSRF)', sub: '1,024 reports · 12 weaknesses' },
    { type: 'class', label: 'Insecure Direct Object Reference (IDOR)', sub: '987 reports · 15 weaknesses' },
    { type: 'class', label: 'SQL Injection', sub: '876 reports · 11 weaknesses' },
    { type: 'weakness', label: 'Reflected XSS', sub: 'Cross-site Scripting (XSS) · 1,847 reports' },
    { type: 'weakness', label: 'Stored XSS', sub: 'Cross-site Scripting (XSS) · 1,234 reports' },
    { type: 'weakness', label: 'Blind SSRF', sub: 'Server-Side Request Forgery · 412 reports' },
    { type: 'weakness', label: 'DOM-based XSS', sub: 'Cross-site Scripting (XSS) · 412 reports' },
    { type: 'program', label: 'Shopify', sub: '312 disclosed reports' },
    { type: 'program', label: 'GitHub', sub: '287 disclosed reports' },
    { type: 'program', label: 'WordPress', sub: '256 disclosed reports' },
    { type: 'program', label: 'PayPal', sub: '198 disclosed reports' },
    { type: 'program', label: 'Uber', sub: '176 disclosed reports' },
    { type: 'program', label: 'Cloudflare', sub: '165 disclosed reports' },
    { type: 'program', label: 'Airbnb', sub: '143 disclosed reports' },
    { type: 'weakness', label: 'Account Takeover via Password Reset', sub: 'Authentication Bypass · 98 reports' },
    { type: 'weakness', label: 'CSRF via JSON Content-Type', sub: 'Cross-Site Request Forgery · 87 reports' },
    { type: 'weakness', label: 'SSTI to RCE', sub: 'Remote Code Execution · 64 reports' },
  ];

  let selectedIdx = -1;

  // --- Search overlay ---
  function openSearch() {
    findOverlay.style.display = 'flex';
    searchInput.value = '';
    searchInput.focus();
    renderSearchResults('');
    selectedIdx = -1;
  }

  function closeSearch() {
    findOverlay.style.display = 'none';
  }

  function renderSearchResults(query) {
    const q = query.toLowerCase().trim();

    if (!q) {
      findList.innerHTML = `
        <div class="find-hint">
          <p>Search across 15,244 disclosed reports, 215 weaknesses, and 428 programs. Use filters like <code>class:xss</code> or <code>program:shopify</code>.</p>
          <div>
            <button class="chip" data-q="Cross-site Scripting">Cross-site Scripting</button>
            <button class="chip" data-q="SSRF">SSRF</button>
            <button class="chip" data-q="IDOR">IDOR</button>
            <button class="chip" data-q="SQL Injection">SQL Injection</button>
            <button class="chip" data-q="Authentication Bypass">Authentication Bypass</button>
            <button class="chip" data-q="CSRF">CSRF</button>
            <button class="chip" data-q="RCE">RCE</button>
            <button class="chip" data-q="Open Redirect">Open Redirect</button>
          </div>
        </div>`;
      // Rebind chip clicks
      findList.querySelectorAll('.chip').forEach(btn => {
        btn.addEventListener('click', () => {
          searchInput.value = btn.dataset.q;
          renderSearchResults(btn.dataset.q);
          searchInput.focus();
        });
      });
      return;
    }

    const results = searchData.filter(item =>
      item.label.toLowerCase().includes(q) ||
      item.sub.toLowerCase().includes(q) ||
      item.type.includes(q)
    );

    if (results.length === 0) {
      findList.innerHTML = `<p class="find-none">No results for "${query}"</p>`;
      return;
    }

    // Group by type
    const grouped = {};
    results.forEach(r => {
      if (!grouped[r.type]) grouped[r.type] = [];
      grouped[r.type].push(r);
    });

    let html = '';
    const typeLabels = { class: 'Vulnerability classes', weakness: 'Weaknesses', program: 'Programs' };

    for (const [type, items] of Object.entries(grouped)) {
      html += `<h3>${typeLabels[type] || type}</h3>`;
      items.forEach((item, idx) => {
        html += `
          <button class="find-item" data-label="${item.label}">
            <span>${item.label} <i>${item.type}</i></span>
            <small>${item.sub}</small>
          </button>`;
      });
    }

    findList.innerHTML = html;
    selectedIdx = -1;

    // Bind clicks
    findList.querySelectorAll('.find-item').forEach(btn => {
      btn.addEventListener('click', () => {
        closeSearch();
        openPanel(btn.dataset.label);
      });
    });
  }

  // --- Side Panel ---
  function openPanel(title) {
    const cls = searchData.find(d => d.label === title);
    if (!cls) return;

    sidePanel.querySelector('h2').textContent = cls.label;
    sidePanel.querySelector('.figure').textContent = cls.sub;
    sidePanel.querySelector('.tag').textContent = cls.type.toUpperCase();
    sidePanel.classList.add('open');
    sidePanel.setAttribute('aria-hidden', 'false');

    // Collapse hero & stats
    hero.classList.add('gone');
    stats.classList.add('gone');

    // Add breadcrumb
    const crumbs = document.querySelector('.crumbs');
    const existingBreadcrumb = crumbs.querySelector('.breadcrumb-item');
    if (existingBreadcrumb) existingBreadcrumb.remove();

    const span = document.createElement('span');
    span.className = 'breadcrumb-item';
    span.innerHTML = `<i>›</i> <b>${cls.label}</b>`;
    crumbs.appendChild(span);
  }

  function closePanel() {
    sidePanel.classList.remove('open');
    sidePanel.setAttribute('aria-hidden', 'true');
    hero.classList.remove('gone');
    stats.classList.remove('gone');

    const bc = document.querySelector('.breadcrumb-item');
    if (bc) bc.remove();
  }

  // --- Lens toggle (Vulnerabilities / Programs / CVEs) ---
  const lensButtons = document.querySelectorAll('.lens button');
  lensButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      lensButtons.forEach(b => b.setAttribute('aria-pressed', 'false'));
      btn.setAttribute('aria-pressed', 'true');
      closePanel();
    });
  });

  // --- Event Listeners ---
  findBtn.addEventListener('click', openSearch);
  searchBtn.addEventListener('click', openSearch);
  escBtn.addEventListener('click', closeSearch);

  exploreBtn.addEventListener('click', () => {
    hero.classList.add('gone');
  });

  findOverlay.addEventListener('click', e => {
    if (e.target === findOverlay) closeSearch();
  });

  searchInput.addEventListener('input', () => {
    renderSearchResults(searchInput.value);
  });

  // Keyboard navigation in search
  searchInput.addEventListener('keydown', e => {
    const items = findList.querySelectorAll('.find-item');
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      selectedIdx = Math.min(selectedIdx + 1, items.length - 1);
      updateSelection(items);
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      selectedIdx = Math.max(selectedIdx - 1, -1);
      updateSelection(items);
    } else if (e.key === 'Enter' && selectedIdx >= 0 && items[selectedIdx]) {
      items[selectedIdx].click();
    } else if (e.key === 'Escape') {
      closeSearch();
    }
  });

  function updateSelection(items) {
    items.forEach((el, i) => {
      el.classList.toggle('on', i === selectedIdx);
    });
    if (selectedIdx >= 0 && items[selectedIdx]) {
      items[selectedIdx].scrollIntoView({ block: 'nearest' });
    }
  }

  // Global keyboard shortcuts
  document.addEventListener('keydown', e => {
    if (e.key === 'f' && !e.ctrlKey && !e.metaKey && document.activeElement.tagName !== 'INPUT') {
      e.preventDefault();
      openSearch();
    }
    if (e.key === 'Escape') {
      if (findOverlay.style.display !== 'none') {
        closeSearch();
      } else if (sidePanel.classList.contains('open')) {
        closePanel();
      }
    }
  });

  // Canvas strip click → open panel
  window.addEventListener('strip-click', e => {
    const cls = e.detail;
    sidePanel.querySelector('h2').textContent = cls.name;
    sidePanel.querySelector('.figure').textContent = `${cls.count.toLocaleString()} reports · ${cls.weaknesses} weaknesses`;
    sidePanel.querySelector('.tag').textContent = 'VULNERABILITY CLASS';
    sidePanel.classList.add('open');
    sidePanel.setAttribute('aria-hidden', 'false');

    hero.classList.add('gone');
    stats.classList.add('gone');

    const crumbs = document.querySelector('.crumbs');
    const existingBreadcrumb = crumbs.querySelector('.breadcrumb-item');
    if (existingBreadcrumb) existingBreadcrumb.remove();

    const span = document.createElement('span');
    span.className = 'breadcrumb-item';
    span.innerHTML = `<i>›</i> <b>${cls.name}</b>`;
    crumbs.appendChild(span);
  });

  // Close panel when clicking breadcrumb lens
  document.querySelector('.crumbs').addEventListener('click', e => {
    if (e.target.closest('.lens')) {
      closePanel();
    }
  });

  // Stats buttons
  document.getElementById('weaknessBtn').addEventListener('click', () => {
    const lens = document.querySelectorAll('.lens button');
    lens[0].click(); // Switch to Vulnerabilities view
  });

  document.getElementById('programsBtn').addEventListener('click', () => {
    const lens = document.querySelectorAll('.lens button');
    lens[1].click(); // Switch to Programs view
  });

})();
