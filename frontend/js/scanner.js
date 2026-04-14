/**
 * QR code scanner module — wraps html5-qrcode.
 *
 * Responsibilities:
 * - Camera lifecycle (start / stop).
 * - Extract a URL from scanned text (ignores non-URL payloads).
 * - Prefer the rear/environment camera on mobile.
 */

let _scanner = null;
let _scanning = false;

/** Whether the scanner is currently active. */
export function isScanning() {
  return _scanning;
}

/**
 * Start the QR camera scanner.
 * @param {(url: string) => void} onUrl  Called once a valid HTTP(S) URL is decoded.
 * @throws {Error} with a user-friendly message if the camera cannot be started.
 */
export async function startScan(onUrl) {
  if (_scanning) return;

  if (!window.Html5Qrcode) {
    throw new Error("QR library not loaded. Please refresh the page.");
  }

  let devices;
  try {
    devices = await Html5Qrcode.getCameras();
  } catch {
    throw new Error("Camera permission denied. Please allow camera access and try again.");
  }

  if (!devices.length) {
    throw new Error("No camera found on this device. Please enter the URL manually.");
  }

  _scanner = new Html5Qrcode("qr-reader");
  const cameraId = _pickCamera(devices).id;

  try {
    await _scanner.start(
      cameraId,
      { fps: 10, qrbox: { width: 240, height: 240 } },
      (text) => {
        const url = _extractUrl(text);
        if (url) onUrl(url);
      },
      () => {}, // per-frame scan errors are expected; suppress them
    );
  } catch (err) {
    _scanner = null;
    throw new Error(`Could not start camera: ${err?.message ?? err}`);
  }

  _scanning = true;
}

/** Stop and tear down the scanner. Safe to call when not scanning. */
export async function stopScan() {
  if (!_scanning || !_scanner) return;
  try {
    await _scanner.stop();
  } finally {
    _scanner = null;
    _scanning = false;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function _pickCamera(devices) {
  return (
    devices.find((d) => /back|rear|environment/i.test(d.label)) ?? devices[0]
  );
}

function _extractUrl(text) {
  const trimmed = text.trim();
  return /^https?:\/\//i.test(trimmed) ? trimmed : null;
}
