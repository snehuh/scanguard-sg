/**
 * sessionStorage wrapper for scan history.
 *
 * - Stores at most MAX_HISTORY entries per browser session.
 * - Data is automatically cleared when the tab is closed (sessionStorage).
 * - URL is truncated before storage to prevent oversized payloads.
 */

const STORAGE_KEY = "scanguard_history";
const MAX_HISTORY = 10;

/**
 * Prepend a scan result to session history.
 * @param {string} url
 * @param {{ verdict: string, risk_score: number }} result
 */
export function saveScan(url, result) {
  const history = getScans();
  history.unshift({
    url: _truncate(url, 80),
    verdict: result.verdict,
    risk_score: result.risk_score,
    ts: new Date().toISOString(),
  });
  _write(history.slice(0, MAX_HISTORY));
}

/** Return saved scans (newest first), or [] on any error. */
export function getScans() {
  try {
    return JSON.parse(sessionStorage.getItem(STORAGE_KEY) ?? "[]");
  } catch {
    return [];
  }
}

/** Remove all session history. */
export function clearScans() {
  sessionStorage.removeItem(STORAGE_KEY);
}

function _write(data) {
  try {
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(data));
  } catch {
    // sessionStorage may be blocked in private/incognito — fail silently
  }
}

function _truncate(str, max) {
  return str.length > max ? `${str.slice(0, max)}…` : str;
}
