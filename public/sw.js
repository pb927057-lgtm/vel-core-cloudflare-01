// Service Worker para VEL PWA — Almacena EXCLUSIVAMENTE recursos estáticos de la interfaz.
// PROHIBIDO: No almacenar respuestas de API, tokens, mensajes, claves ni datos personales.
// Los datos personales residen únicamente en el almacenamiento IndexedDB local de cada teléfono.

const CACHE_NAME = 'vel-static-cache-v6';

// Activos estáticos esenciales de la interfaz
const PRECACHE_ASSETS = [
  '/',
  '/index.html',
  '/manifest.json',
  '/icon.svg',
  '/pwa-192x192.png',
  '/pwa-512x512.png',
  '/pwa-maskable-512x512.png',
  '/apple-touch-icon.png'
];

function isSensitiveOrDynamicPath(pathname) {
  return (
    pathname.startsWith('/api/') ||
    pathname.endsWith('.zip')
  );
}

function isViteDevModulePath(pathname, search) {
  return (
    pathname.startsWith('/src/') ||
    pathname.startsWith('/@') ||
    pathname.startsWith('/node_modules/') ||
    (typeof search === 'string' && search.includes('t='))
  );
}

function isPreviewOrDevHost(hostname) {
  const normalized = (hostname || '').toLowerCase();
  return (
    normalized === 'localhost' ||
    normalized === '127.0.0.1' ||
    normalized === '[::1]' ||
    /^ais-(dev|pre)-.*\.run\.app$/i.test(normalized) ||
    normalized.endsWith('.scf.usercontent.goog')
  );
}

self.addEventListener('install', (event) => {
  self.skipWaiting();
  if (isPreviewOrDevHost(self.location.hostname)) {
    return;
  }
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(PRECACHE_ASSETS).catch((err) => {
        console.warn('Precache parcial de activos estáticos VEL:', err);
      });
    })
  );
});

self.addEventListener('activate', (event) => {
  if (isPreviewOrDevHost(self.location.hostname)) {
    event.waitUntil(
      caches
        .keys()
        .then((cacheNames) =>
          Promise.all(
            cacheNames
              .filter((name) => /^vel-static-cache-/i.test(name))
              .map((name) => caches.delete(name))
          )
        )
        .then(() => self.registration.unregister().catch(() => false))
    );
    return;
  }

  event.waitUntil(
    caches
      .keys()
      .then((cacheNames) =>
        Promise.all(
          cacheNames
            .filter((name) => name !== CACHE_NAME)
            .map((name) => caches.delete(name))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (event) => {
  if (isPreviewOrDevHost(self.location.hostname)) {
    return;
  }

  const request = event.request;

  if (request.method !== 'GET') {
    return;
  }

  // Nunca interceptar ni almacenar solicitudes autenticadas
  if (request.headers && request.headers.get('Authorization')) {
    return;
  }

  const url = new URL(request.url);

  // Nunca interceptar orígenes externos (Firebase, Mercado Pago, Blogger, WSS)
  if (url.origin !== self.location.origin) {
    return;
  }

  // Nunca interceptar ni cachear módulos de desarrollo Vite (Preview)
  if (isViteDevModulePath(url.pathname, url.search)) {
    return;
  }

  // Nunca interceptar ni cachear endpoints de backend ni descargas ZIP
  if (isSensitiveOrDynamicPath(url.pathname)) {
    return;
  }

  // Navegación SPA: Network-First para recibir actualizaciones, con fallback a shell estático
  if (request.mode === 'navigate') {
    event.respondWith(
      fetch(request)
        .then((response) => {
          if (response && response.status === 200) {
            const copy = response.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put('/index.html', copy));
          }
          return response;
        })
        .catch(() => {
          return caches.match('/index.html').then((cached) => cached || caches.match('/'));
        })
    );
    return;
  }

  // Activos estáticos exclusivamente (JS, CSS, imágenes, fuentes, manifest.json)
  event.respondWith(
    caches.match(request).then((cachedResponse) => {
      const networkFetch = fetch(request)
        .then((networkResponse) => {
          if (!networkResponse || networkResponse.status !== 200) {
            return networkResponse;
          }

          const contentType = (networkResponse.headers.get('content-type') || '').toLowerCase();
          const isAllowedStatic =
            contentType.includes('javascript') ||
            contentType.includes('text/css') ||
            contentType.includes('image/') ||
            contentType.includes('font/') ||
            contentType.includes('application/manifest+json') ||
            url.pathname === '/manifest.json' ||
            url.pathname.startsWith('/assets/');

          // Nunca cachear respuestas application/json de datos ni blobs privados
          if (isAllowedStatic && !contentType.includes('application/json')) {
            const responseToCache = networkResponse.clone();
            caches.open(CACHE_NAME).then((cache) => cache.put(request, responseToCache));
          }

          return networkResponse;
        })
        .catch(() => cachedResponse);

      return cachedResponse || networkFetch;
    })
  );
});
