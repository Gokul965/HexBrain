/**
 * HexBrain Canvas Visualization
 * Renders an organic, sparse map of vulnerability strips with connecting curves.
 * Matches the original's aesthetic: subtle, dark, minimal, with data-driven density.
 */

(function () {
  'use strict';

  const canvas = document.querySelector('.canvas');
  const svg = document.querySelector('.labels');
  const ctx = canvas.getContext('2d');

  // --- Exact color palette from HexBrain ---
  const BG      = '#13120e';
  const RAISE   = '#1f1d17';
  const LINE    = '#322f25';
  const DIM     = '#8f8874';
  const INK     = '#efe6d0';
  const HOT     = '#ff6a3d';

  // --- Vulnerability classes with real data ---
  const classes = [
    { name: 'Cross-site Scripting (XSS)',             count: 4127, weaknesses: 87 },
    { name: 'Improper Access Control',                count: 2156, weaknesses: 34 },
    { name: 'Information Disclosure',                 count: 1893, weaknesses: 28 },
    { name: 'Server-Side Request Forgery',            count: 1024, weaknesses: 12 },
    { name: 'Insecure Direct Object Reference',       count: 987,  weaknesses: 15 },
    { name: 'SQL Injection',                          count: 876,  weaknesses: 11 },
    { name: 'Cross-Site Request Forgery',             count: 654,  weaknesses: 8 },
    { name: 'Open Redirect',                          count: 543,  weaknesses: 6 },
    { name: 'Business Logic Errors',                  count: 498,  weaknesses: 9 },
    { name: 'Privilege Escalation',                   count: 432,  weaknesses: 7 },
    { name: 'Authentication Bypass',                  count: 398,  weaknesses: 5 },
    { name: 'Remote Code Execution',                  count: 321,  weaknesses: 4 },
    { name: 'Denial of Service',                      count: 287,  weaknesses: 6 },
    { name: 'Race Condition',                         count: 198,  weaknesses: 3 },
    { name: 'Path Traversal',                         count: 176,  weaknesses: 4 },
    { name: 'XML External Entities',                  count: 134,  weaknesses: 2 },
    { name: 'Memory Corruption',                      count: 98,   weaknesses: 3 },
    { name: 'Cryptographic Issues',                   count: 87,   weaknesses: 2 },
  ];

  // seeded random for deterministic layout
  let _seed = 42;
  function srand(s) { _seed = s; }
  function rand() { _seed = (_seed * 16807 + 0) % 2147483647; return (_seed - 1) / 2147483646; }

  // --- State ---
  let W, H, dpr;
  let camX = 0, camY = 0, camScale = 1;
  let dragging = false, dragStartX = 0, dragStartY = 0, camStartX = 0, camStartY = 0;
  let strips = [];
  let curves = [];
  let hoverStrip = null;
  let animFrame = null;

  // --- Layout constants ---
  const STRIP_GAP = 6;            // gap between strips (px in world space)
  const LABEL_OFFSET = 16;        // label distance from strip edge
  const CURVE_COUNT = 50;         // number of connecting curves

  function resize() {
    dpr = window.devicePixelRatio || 1;
    W = window.innerWidth;
    H = window.innerHeight;
    canvas.width  = W * dpr;
    canvas.height = H * dpr;
    canvas.style.width  = W + 'px';
    canvas.style.height = H + 'px';
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    svg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    buildLayout();
    render();
  }

  function buildLayout() {
    srand(42);
    strips = [];

    const totalReports = classes.reduce((s, c) => s + c.count, 0);
    const marginTop    = 90;
    const marginBottom = 120;
    const usableH      = H - marginTop - marginBottom;
    const stripW       = Math.min(360, W * 0.26);
    const centerX      = W / 2;

    let y = marginTop;

    classes.forEach((cls, i) => {
      // Height proportional to report count, with a reasonable minimum
      const fraction = cls.count / totalReports;
      const h = Math.max(8, fraction * usableH);

      // Generate weakness sub-bands within each strip
      const bands = [];
      let remaining = cls.weaknesses;
      let bandY = 0;
      while (remaining > 0 && bandY < h) {
        const bandH = Math.max(1.5, (h / cls.weaknesses) * (0.6 + rand() * 0.8));
        const gap = rand() * 1.2;
        bands.push({ y: bandY, h: Math.min(bandH, h - bandY) });
        bandY += bandH + gap;
        remaining--;
      }

      // Generate individual report lines within each band
      const lines = [];
      const lineCount = Math.min(cls.count, Math.floor(h / 0.8));
      for (let j = 0; j < lineCount; j++) {
        const ly = rand() * h;
        const len = (0.15 + rand() * 0.7) * stripW;
        const lx = rand() * (stripW - len);
        const alpha = 0.08 + rand() * 0.25;
        lines.push({ x: lx, y: ly, len, alpha });
      }

      strips.push({
        x: centerX - stripW / 2,
        y,
        w: stripW,
        h,
        cls,
        bands,
        lines,
      });

      y += h + STRIP_GAP;
    });

    // Center the map vertically
    const totalH = y - STRIP_GAP - marginTop;
    const offsetNeeded = (usableH - totalH) / 2;
    if (offsetNeeded > 0) {
      strips.forEach(s => { s.y += offsetNeeded; });
    }

    // Generate connecting curves between related strips
    curves = [];
    srand(123);
    for (let i = 0; i < CURVE_COUNT; i++) {
      const a = Math.floor(rand() * strips.length);
      let b = Math.floor(rand() * strips.length);
      if (b === a) b = (b + 1) % strips.length;
      const fromStrip = strips[a];
      const toStrip   = strips[b];
      const fromY = fromStrip.y + rand() * fromStrip.h;
      const toY   = toStrip.y   + rand() * toStrip.h;
      const side  = rand() > 0.5 ? 1 : -1; // curve left or right of center
      curves.push({
        fromX: fromStrip.x + fromStrip.w / 2,
        fromY,
        toX:   toStrip.x + toStrip.w / 2,
        toY,
        side,
        alpha: 0.025 + rand() * 0.04,
      });
    }
  }

  // --- Rendering ---
  function render() {
    ctx.clearRect(0, 0, W, H);
    ctx.save();
    ctx.translate(camX, camY);
    ctx.scale(camScale, camScale);

    // 1) Draw connecting curves (very subtle)
    curves.forEach(c => {
      ctx.beginPath();
      ctx.strokeStyle = DIM;
      ctx.globalAlpha = c.alpha;
      ctx.lineWidth = 0.5;
      const cpOffset = c.side * (60 + Math.abs(c.toY - c.fromY) * 0.3);
      ctx.moveTo(c.fromX, c.fromY);
      ctx.bezierCurveTo(
        c.fromX + cpOffset, c.fromY,
        c.toX + cpOffset,   c.toY,
        c.toX,              c.toY
      );
      ctx.stroke();
    });
    ctx.globalAlpha = 1;

    // 2) Draw strips
    strips.forEach((strip, idx) => {
      const isHover = hoverStrip === idx;

      // Subtle background band
      ctx.fillStyle = RAISE;
      ctx.globalAlpha = isHover ? 0.9 : 0.5;
      ctx.fillRect(strip.x, strip.y, strip.w, strip.h);
      ctx.globalAlpha = 1;

      // Top & bottom border lines
      ctx.strokeStyle = LINE;
      ctx.lineWidth = 0.5;
      ctx.globalAlpha = 0.6;
      ctx.beginPath();
      ctx.moveTo(strip.x, strip.y);
      ctx.lineTo(strip.x + strip.w, strip.y);
      ctx.moveTo(strip.x, strip.y + strip.h);
      ctx.lineTo(strip.x + strip.w, strip.y + strip.h);
      ctx.stroke();
      ctx.globalAlpha = 1;

      // Report lines — the core data visualization
      const lineColor = isHover ? HOT : INK;
      strip.lines.forEach(line => {
        ctx.fillStyle = lineColor;
        ctx.globalAlpha = isHover ? line.alpha * 1.5 : line.alpha;
        ctx.fillRect(strip.x + line.x, strip.y + line.y, line.len, 0.8);
      });
      ctx.globalAlpha = 1;
    });

    ctx.restore();
    updateLabels();
  }

  function updateLabels() {
    // Clear previous labels
    while (svg.firstChild) svg.removeChild(svg.firstChild);

    strips.forEach((strip, idx) => {
      const isHover = hoverStrip === idx;

      // Transform world coords → screen coords
      const sx  = (strip.x - LABEL_OFFSET) * camScale + camX;
      const sy  = (strip.y + strip.h / 2) * camScale + camY;
      const erx = (strip.x + strip.w + LABEL_OFFSET) * camScale + camX;

      // Cull off-screen labels
      if (sy < -30 || sy > H + 30) return;

      const fontSize = Math.max(8.5, 11 * camScale);

      // Class name (left of strip)
      const nameEl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      nameEl.setAttribute('x', sx);
      nameEl.setAttribute('y', sy);
      nameEl.setAttribute('text-anchor', 'end');
      nameEl.setAttribute('fill', isHover ? INK : DIM);
      nameEl.setAttribute('font-size', fontSize);
      nameEl.setAttribute('dominant-baseline', 'central');
      nameEl.textContent = strip.cls.name;
      svg.appendChild(nameEl);

      // Count (right of strip)
      const countEl = document.createElementNS('http://www.w3.org/2000/svg', 'text');
      countEl.setAttribute('x', erx);
      countEl.setAttribute('y', sy);
      countEl.setAttribute('text-anchor', 'start');
      countEl.setAttribute('fill', isHover ? HOT : DIM);
      countEl.setAttribute('font-size', Math.max(7.5, 9.5 * camScale));
      countEl.setAttribute('dominant-baseline', 'central');
      countEl.textContent = strip.cls.count.toLocaleString();
      svg.appendChild(countEl);
    });
  }

  // --- Interaction: Drag to Pan ---
  canvas.addEventListener('mousedown', e => {
    dragging = true;
    canvas.style.cursor = 'grabbing';
    dragStartX = e.clientX;
    dragStartY = e.clientY;
    camStartX = camX;
    camStartY = camY;
  });

  window.addEventListener('mousemove', e => {
    if (dragging) {
      camX = camStartX + (e.clientX - dragStartX);
      camY = camStartY + (e.clientY - dragStartY);
      render();
      return;
    }

    // Hover detection
    const mx = (e.clientX - camX) / camScale;
    const my = (e.clientY - camY) / camScale;
    let found = null;
    for (let i = 0; i < strips.length; i++) {
      const s = strips[i];
      if (mx >= s.x && mx <= s.x + s.w && my >= s.y && my <= s.y + s.h) {
        found = i;
        break;
      }
    }
    if (found !== hoverStrip) {
      hoverStrip = found;
      canvas.style.cursor = found !== null ? 'pointer' : 'grab';
      render();
    }
  });

  window.addEventListener('mouseup', () => {
    dragging = false;
    canvas.style.cursor = hoverStrip !== null ? 'pointer' : 'grab';
  });

  // --- Interaction: Scroll to Zoom ---
  canvas.addEventListener('wheel', e => {
    e.preventDefault();
    const factor = e.deltaY > 0 ? 0.93 : 1.07;
    const newScale = Math.max(0.25, Math.min(6, camScale * factor));
    const mx = e.clientX;
    const my = e.clientY;
    camX = mx - (mx - camX) * (newScale / camScale);
    camY = my - (my - camY) * (newScale / camScale);
    camScale = newScale;
    render();
  }, { passive: false });

  // --- Interaction: Click ---
  canvas.addEventListener('click', e => {
    if (Math.abs(e.clientX - dragStartX) > 4 || Math.abs(e.clientY - dragStartY) > 4) return;
    const mx = (e.clientX - camX) / camScale;
    const my = (e.clientY - camY) / camScale;
    for (const strip of strips) {
      if (mx >= strip.x && mx <= strip.x + strip.w && my >= strip.y && my <= strip.y + strip.h) {
        window.dispatchEvent(new CustomEvent('strip-click', { detail: strip.cls }));
        break;
      }
    }
  });

  // --- Touch support ---
  let lastTouchDist = 0;
  let touchStartX = 0, touchStartY = 0;

  canvas.addEventListener('touchstart', e => {
    if (e.touches.length === 1) {
      dragging = true;
      touchStartX = e.touches[0].clientX;
      touchStartY = e.touches[0].clientY;
      dragStartX = touchStartX;
      dragStartY = touchStartY;
      camStartX = camX;
      camStartY = camY;
    } else if (e.touches.length === 2) {
      dragging = false;
      lastTouchDist = Math.hypot(
        e.touches[0].clientX - e.touches[1].clientX,
        e.touches[0].clientY - e.touches[1].clientY
      );
    }
  }, { passive: true });

  canvas.addEventListener('touchmove', e => {
    e.preventDefault();
    if (e.touches.length === 1 && dragging) {
      camX = camStartX + (e.touches[0].clientX - dragStartX);
      camY = camStartY + (e.touches[0].clientY - dragStartY);
      render();
    } else if (e.touches.length === 2) {
      const dist = Math.hypot(
        e.touches[0].clientX - e.touches[1].clientX,
        e.touches[0].clientY - e.touches[1].clientY
      );
      const factor = dist / lastTouchDist;
      camScale = Math.max(0.25, Math.min(6, camScale * factor));
      lastTouchDist = dist;
      render();
    }
  }, { passive: false });

  canvas.addEventListener('touchend', () => { dragging = false; });

  // --- Init ---
  window.addEventListener('resize', () => { resize(); });
  resize();
})();
