/* Service worker for Today's Mail.
 *
 * Strategy:
 *  - Navigations (/, /today) are network-first, so the digest is always
 *    fresh when online, with the last-seen page as an offline fallback.
 *  - /today.json is network-first too: offline keeps the last known digest.
 *  - Static assets are cache-first (they never change).
 */
const CACHE = "usps-today-v1";
const APP_SHELL = [
  "/",
  "/today",
  "/static/manifest.webmanifest",
  "/static/sw.js",
  "/static/icons/apple-touch-icon.png",
  "/static/icons/icon-192.png",
  "/static/icons/icon-512.png"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE)
      .then((cache) => cache.addAll(APP_SHELL))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;

  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // Pages: always try the network first, fall back to the cached page.
  if (req.mode === "navigate") {
    event.respondWith(
      fetch(req)
        .then((res) => {
          if (res.ok) {
            const copy = res.clone();
            caches.open(CACHE).then((cache) => cache.put("/today", copy));
          }
          return res;
        })
        .catch(() => caches.match(req).then((hit) => hit || caches.match("/today")))
    );
    return;
  }

  // The live digest JSON: network-first, stale fallback for offline use.
  if (url.pathname === "/today.json") {
    event.respondWith(
      fetch(req)
        .then((res) => {
          const copy = res.clone();
          caches.open(CACHE).then((cache) => cache.put(req, copy));
          return res;
        })
        .catch(() => caches.match(req))
    );
    return;
  }

  // Everything else (static assets): cache-first.
  event.respondWith(
    caches.match(req).then(
      (hit) =>
        hit ||
        fetch(req).then((res) => {
          if (res.ok && url.pathname.startsWith("/static/")) {
            const copy = res.clone();
            caches.open(CACHE).then((cache) => cache.put(req, copy));
          }
          return res;
        })
    )
  );
});
