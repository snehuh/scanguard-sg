/**
 * Backend API client.
 *
 * Security notes:
 * - Uses fetch with a hard timeout (AbortSignal) to prevent hanging requests.
 * - API base URL is resolved from the current hostname so that the same
 *   static bundle works on both localhost and production.
 * - Never logs or exposes the full URL beyond what the user already typed.
 */

const API_BASE =
  ["localhost", "127.0.0.1"].includes(window.location.hostname)
    ? "http://localhost:5000"
    : "https://api.scanguard.sg";

const TIMEOUT_MS = 15_000;

/**
 * Submit a URL for safety analysis.
 * @param {string} url
 * @returns {Promise<{ verdict: string, risk_score: number, reasons: string[], is_sg_targeted: boolean }>}
 * @throws {ApiError}
 */
export async function checkUrl(url) {
  let response;
  try {
    response = await fetch(`${API_BASE}/api/check`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (err) {
    if (err.name === "TimeoutError") throw new ApiError("Request timed out.", 0);
    throw new ApiError("Network error — check your connection.", 0);
  }

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new ApiError(data.error ?? "Request failed.", response.status);
  }
  return data;
}

export class ApiError extends Error {
  /**
   * @param {string} message  Human-readable error text.
   * @param {number} status   HTTP status code (0 for network-level errors).
   */
  constructor(message, status) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}
