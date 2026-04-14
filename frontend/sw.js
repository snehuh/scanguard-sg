/**
 * ScanGuard SG — Service Worker
 *
 * Strategy:
 * - App shell (HTML/CSS/JS): cache-first for instant load.
 * - API requests (/api/*): network-only; return a JSON error when offline.
 * - Old cache versions are deleted on activation.
 */

const CACHE = "scanguard-v1";

const SHELL = [
  "/",
  "/index.html",
  "/offline.html",
  "/css/styles.css",
  "/js/app.js",
  "/js/scanner.js",
  "/js/api.js",
  "/js/ui.js",
  "/js/storage.js",
  "/manifest.json",
];

// ── Install: pre-cache the app shell ────────────────────────────────────────
self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE).then((cache) => cache.addAll(SHELL)),
  );
  self.skipWaiting();
});

// ── Activate: remove stale caches ───────────────────────────────────────────
self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches
      .keys()
      .then((keys) =>
        Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))),
      ),
  );
  self.clients.claim();
});

// ── Fetch ────────────────────────────────────────────────────────────────────
self.addEventListener("fetch", (e) => {
  const { request } = e;
  const url = new URL(request.url);

  // API calls: always go to the network; return a safe offline response on failure
  if (url.pathname.startsWith("/api/")) {
    e.respondWith(
      fetch(request).catch(() =>
        new Response(
          JSON.stringify({ error: "You are offline. Please reconnect and try again." }),
          {
            status: 503,
            headers: {
              "Content-Type": "application/json",
              "Cache-Control": "no-store",
            },
          },
        ),
      ),
    );
    return;
  }

  // Shell assets: cache-first, fallback to network, then offline page
  e.respondWith(
    caches.match(request).then(
      (cached) =>
        cached ??
        fetch(request)
          .then((res) => {
            // Opportunistically cache successful GET responses for shell assets
            if (res.ok && request.method === "GET") {
              caches.open(CACHE).then((c) => c.put(request, res.clone()));
            }
            return res;
          })
          .catch(() => caches.match("/offline.html")),
    ),
  );
});
