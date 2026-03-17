/* ============================================================
   SECOPS AI PLATFORM — FRONTEND JS v2
   Handles: sidebar, chat engine, AI message formatter
============================================================ */

// ── Sidebar ──────────────────────────────────────────────────
function openSidebar() {
  document.getElementById('sidebar').classList.add('open');
  const bd = document.getElementById('sidebarBackdrop');
  if (bd) bd.classList.add('visible');
}
function closeSidebar() {
  document.getElementById('sidebar').classList.remove('open');
  const bd = document.getElementById('sidebarBackdrop');
  if (bd) bd.classList.remove('visible');
}

// ── HTML escape ───────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── AI Message Formatter ─────────────────────────────────────
function formatAIMessage(text, isDark) {
  const lines = text.split('\n');
  let html = '<div class="fmt-content">';

  lines.forEach(line => {
    const t = line.trim();
    if (!t) { html += '<div style="height:5px"></div>'; return; }

    // Section header [Title]
    const hm = t.match(/^\[(.+)\]$/);
    if (hm) {
      const title = hm[1];
      let cls = isDark ? 'fmt-header-indigo' : '';
      if (/action|patch|recommendation|remediation/i.test(title)) cls = 'fmt-header-green';
      if (/impact|risk|vulnerabilit/i.test(title)) cls = 'fmt-header-red';
      if (/executive|summary/i.test(title)) cls = isDark ? 'fmt-header-indigo' : '';
      html += `<div class="fmt-header ${cls}">${esc(title)}</div>`;
      return;
    }

    // Bullet point
    if (t.startsWith('-')) {
      const dot = isDark ? '▹' : '•';
      html += `<div class="fmt-bullet">
        <span class="fmt-dot">${dot}</span>
        <span>${esc(t.slice(1).trim())}</span>
      </div>`;
      return;
    }

    html += `<div class="fmt-text">${esc(t)}</div>`;
  });

  html += '</div>';
  return html;
}

// ── Render pre-existing AI bubbles that carry data-raw ────────
function renderExistingBubbles(isDark) {
  document.querySelectorAll('[data-raw]').forEach(el => {
    el.innerHTML = formatAIMessage(el.dataset.raw, isDark);
    el.removeAttribute('data-raw');
  });
}

// ── Chat Init (called from each chat template) ────────────────
function initChat(apiEndpoint, mode) {
  const isDark = (mode === 'organization' || mode === 'prowler');

  renderExistingBubbles(isDark);
  scrollToBottom();

  const form    = document.getElementById('chatForm');
  const input   = document.getElementById('chatInput');
  const sendBtn = document.getElementById('chatSendBtn');
  const typing  = document.getElementById('typingIndicator');
  const msgs    = document.getElementById('chatMessages');

  if (!form) return;

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const text = input.value.trim();
    if (!text || sendBtn.disabled) return;

    appendMsg(msgs, 'user', text, isDark, mode);
    input.value = '';
    setDisabled(true);
    typing.classList.remove('hidden');
    scrollToBottom();

    try {
      const res  = await fetch(apiEndpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ prompt: text, mode })
      });
      const data = await res.json();
      typing.classList.add('hidden');

      if (data.status === 'success') {
        appendMsg(msgs, 'ai', data.data, isDark, mode);
      } else {
        appendMsg(msgs, 'ai',
          '[System Error]\n- ' + (data.message || 'Connection error. Please retry.'),
          isDark, mode);
      }
    } catch {
      typing.classList.add('hidden');
      appendMsg(msgs, 'ai',
        '[System Error]\n- Network failure. Check your connection and retry.',
        isDark, mode);
    }

    setDisabled(false);
    input.focus();
    scrollToBottom();
  });

  function setDisabled(v) {
    sendBtn.disabled = v;
    input.disabled   = v;
  }
}

function appendMsg(container, role, content, isDark, mode) {
  const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const end = document.getElementById('messagesEnd');
  const row = document.createElement('div');
  row.className = `chat-row chat-${role}`;

  if (role === 'user') {
    const bubbleClass = isDark ? 'bubble-user-dark' : 'bubble-user';
    const label       = mode === 'prowler' ? 'Analyst' : (isDark ? 'Analyst' : 'You');
    row.innerHTML = `
      <div class="chat-bubble-wrap chat-bubble-right">
        <div class="chat-bubble ${bubbleClass}">${esc(content)}</div>
        <div class="chat-meta meta-right">${label} · ${now}</div>
      </div>`;
  } else {
    const avatarClass = isDark ? 'chat-avatar-indigo' : 'chat-avatar-blue';
    const avatarSVG   = getAvatarSVG(mode);
    const bubbleClass = isDark ? 'bubble-ai-dark' : 'bubble-ai';
    const label       = mode === 'prowler' ? 'Prowler AI' : (isDark ? 'AI Engine' : 'RedTeam AI');

    row.innerHTML = `
      <div class="chat-avatar ${avatarClass}">${avatarSVG}</div>
      <div class="chat-bubble-wrap">
        <div class="chat-bubble ${bubbleClass}">${formatAIMessage(content, isDark)}</div>
        <div class="chat-meta">${label} · ${now}</div>
      </div>`;
  }

  container.insertBefore(row, end);
  scrollToBottom();
}

function getAvatarSVG(mode) {
  if (mode === 'prowler') {
    return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>`;
  }
  if (mode === 'organization') {
    return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="4" y="4" width="16" height="16" rx="2"/><rect x="9" y="9" width="6" height="6"/></svg>`;
  }
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>`;
}

function scrollToBottom() {
  const end = document.getElementById('messagesEnd');
  if (end) setTimeout(() => end.scrollIntoView({ behavior: 'smooth' }), 50);
}

// ── DOM Ready ─────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  renderExistingBubbles(document.documentElement.classList.contains('dark-mode') ||
                        document.querySelector('.dark-mode') !== null);
  scrollToBottom();
});
