/**
 * UI rendering module.
 *
 * Security note: all user-derived or server-derived strings are HTML-escaped
 * via _escapeHtml() before being inserted into the DOM. No innerHTML is ever
 * set from unescaped data.
 */

const VERDICT_META = {
  safe:       { icon: "✅", label: "Safe",       cls: "result--safe" },
  suspicious: { icon: "⚠️",  label: "Suspicious", cls: "result--suspicious" },
  malicious:  { icon: "❌", label: "Malicious",  cls: "result--malicious" },
};

// ── Result card ───────────────────────────────────────────────────────────────

/**
 * Render a verdict result card.
 * @param {{ verdict: string, risk_score: number, reasons: string[], is_sg_targeted: boolean }} result
 * @param {string} url  The URL that was checked.
 */
export function showResult(result, url) {
  const meta = VERDICT_META[result.verdict] ?? VERDICT_META.suspicious;
  const section = _el("result-section");

  _el("result-icon").textContent = meta.icon;
  _el("result-verdict").textContent = meta.label;
  _el("result-url").textContent = _truncate(url, 70);

  const reasonsList = _el("result-reasons");
  reasonsList.innerHTML = result.reasons
    .map((r) => `<li class="result-reason">${_escapeHtml(r)}</li>`)
    .join("");

  const sgBadge = _el("result-sg-badge");
  if (result.is_sg_targeted) {
    sgBadge.textContent = "🇸🇬 SG-targeted scam detected";
    sgBadge.hidden = false;
  } else {
    sgBadge.hidden = true;
  }

  section.className = `card result-card ${meta.cls}`;
  section.hidden = false;
  section.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

export function hideResult() {
  _el("result-section").hidden = true;
}

// ── Loading spinner ───────────────────────────────────────────────────────────

export function showLoading(visible) {
  _el("loading").hidden = !visible;
}

// ── Inline error under input ──────────────────────────────────────────────────

export function showUrlError(msg) {
  const el = _el("url-error");
  el.textContent = msg;
  el.hidden = !msg;
}

export function clearUrlError() {
  showUrlError("");
}

// ── History list ──────────────────────────────────────────────────────────────

/**
 * Render session scan history.
 * @param {Array<{ url: string, verdict: string, ts: string }>} scans
 */
export function renderHistory(scans) {
  const section = _el("history-section");
  const list = _el("history-list");

  if (!scans.length) {
    section.hidden = true;
    return;
  }

  list.innerHTML = scans
    .map(({ url, verdict, ts }) => {
      const meta = VERDICT_META[verdict] ?? VERDICT_META.suspicious;
      return `<li class="history-item history-item--${_escapeHtml(verdict)}">
        <span class="history-icon" aria-hidden="true">${meta.icon}</span>
        <span class="history-url">${_escapeHtml(url)}</span>
        <span class="history-time">${_formatTime(ts)}</span>
      </li>`;
    })
    .join("");

  section.hidden = false;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _el(id) {
  return document.getElementById(id);
}

function _escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = String(str);
  return div.innerHTML;
}

function _truncate(str, max) {
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

function _formatTime(iso) {
  try {
    return new Date(iso).toLocaleTimeString("en-SG", {
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return "";
  }
}
