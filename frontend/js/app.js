/**
 * ScanGuard SG — main app module.
 *
 * Orchestrates: QR scanning → URL validation → API check → result display →
 *               session history persistence.
 *
 * Service worker registration is also handled here.
 */

import { startScan, stopScan } from "./scanner.js";
import { checkUrl, ApiError } from "./api.js";
import {
  showResult,
  hideResult,
  showLoading,
  showUrlError,
  clearUrlError,
  renderHistory,
} from "./ui.js";
import { saveScan, getScans, clearScans } from "./storage.js";

// ── Service worker ────────────────────────────────────────────────────────────
if ("serviceWorker" in navigator) {
  navigator.serviceWorker
    .register("/sw.js")
    .catch(() => {}); // non-critical; fail silently
}

// ── DOM refs ─────────────────────────────────────────────────────────────────
const btnStart   = document.getElementById("btn-start-scan");
const btnStop    = document.getElementById("btn-stop-scan");
const btnAgain   = document.getElementById("btn-scan-again");
const btnClear   = document.getElementById("btn-clear-history");
const urlInput   = document.getElementById("url-input");
const urlForm    = document.getElementById("url-form");

// ── Camera controls ───────────────────────────────────────────────────────────
btnStart.addEventListener("click", async () => {
  clearUrlError();
  try {
    await startScan(_onQrScanned);
    _setScanUI(true);
  } catch (err) {
    showUrlError(err.message);
  }
});

btnStop.addEventListener("click", async () => {
  await stopScan();
  _setScanUI(false);
});

// ── Manual URL form ───────────────────────────────────────────────────────────
urlForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = urlInput.value.trim();
  if (!url) {
    showUrlError("Please enter a URL to check.");
    urlInput.focus();
    return;
  }
  await _runCheck(url);
});

// ── Result controls ───────────────────────────────────────────────────────────
btnAgain.addEventListener("click", () => {
  hideResult();
  urlInput.value = "";
  urlInput.focus();
  clearUrlError();
});

btnClear.addEventListener("click", () => {
  clearScans();
  renderHistory([]);
});

// ── Core check flow ───────────────────────────────────────────────────────────

async function _onQrScanned(url) {
  await stopScan();
  _setScanUI(false);
  urlInput.value = url;
  await _runCheck(url);
}

async function _runCheck(url) {
  clearUrlError();
  hideResult();
  showLoading(true);

  try {
    const result = await checkUrl(url);
    showResult(result, url);
    saveScan(url, result);
    renderHistory(getScans());
  } catch (err) {
    if (err instanceof ApiError) {
      showUrlError(
        err.status === 429
          ? "Too many checks — please wait a moment and try again."
          : err.message || "Could not analyse this URL. Please try again.",
      );
    } else {
      showUrlError("Network error. Please check your connection and try again.");
    }
  } finally {
    showLoading(false);
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function _setScanUI(scanning) {
  btnStart.hidden = scanning;
  btnStop.hidden  = !scanning;
}

// ── Initial render ────────────────────────────────────────────────────────────
renderHistory(getScans());
