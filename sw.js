// Women AI - Service Worker (PWA + Offline + Caching)
const CACHE_NAME = 'womenai-v3.5';
const STATIC_CACHE = 'womenai-static-v3.5';
const DYNAMIC_CACHE = 'womenai-dynamic-v1';

// Statik dosyalar - her zaman cache'le
const STATIC_ASSETS = [
  '/',
  '/index.html',
  '/style.css',
  '/main.js',
  '/manifest.json',
  '/favicon.svg',
  '/lang/tr.json',
  '/lang/en.json',
  '/lang/zh.json',
  '/icons/icon-192.svg',
  '/icons/icon-512.svg',
  'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap'
];

// API ve dinamik URL'ler - network first
const API_PATTERNS = [
  '/api/',
  '/auth/',
  '/admin'
];

// ========================
// INSTALL - Cache static assets
// ========================
self.addEventListener('install', (event) => {
  console.log('🔧 SW: Installing...');
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        console.log('📦 SW: Caching static assets');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => self.skipWaiting())
      .catch(err => {
        console.warn('⚠️ SW: Some assets failed to cache:', err);
        return self.skipWaiting();
      })
  );
});

// ========================
// ACTIVATE - Clean old caches
// ========================
self.addEventListener('activate', (event) => {
  console.log('✅ SW: Activating...');
  event.waitUntil(
    caches.keys().then(keys => {
      return Promise.all(
        keys
          .filter(key => key !== STATIC_CACHE && key !== DYNAMIC_CACHE && key !== CACHE_NAME)
          .map(key => {
            console.log('🗑️ SW: Deleting old cache:', key);
            return caches.delete(key);
          })
      );
    }).then(() => self.clients.claim())
  );
});

// ========================
// FETCH - Smart caching strategy
// ========================
self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  // Skip non-GET requests
  if (request.method !== 'GET') return;

  // Skip chrome-extension, webpack HMR etc.
  if (!url.protocol.startsWith('http')) return;

  // API calls - Network First (try network, fallback to cache)
  if (API_PATTERNS.some(pattern => url.pathname.includes(pattern))) {
    event.respondWith(networkFirst(request));
    return;
  }

  // Google/Firebase external scripts - Network First
  if (url.hostname.includes('google') || 
      url.hostname.includes('gstatic') || 
      url.hostname.includes('firebase')) {
    event.respondWith(networkFirst(request));
    return;
  }

  // Static assets - Cache First (fast loading)
  event.respondWith(cacheFirst(request));
});

// ========================
// STRATEGIES
// ========================

// Cache First - Statik dosyalar için (hızlı)
async function cacheFirst(request) {
  try {
    const cached = await caches.match(request);
    if (cached) return cached;

    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    
    // Offline fallback for navigation
    if (request.mode === 'navigate') {
      const offlinePage = await caches.match('/');
      if (offlinePage) return offlinePage;
    }
    
    return new Response('Offline', { status: 503, statusText: 'Offline' });
  }
}

// Network First - API ve dinamik içerik için
async function networkFirst(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (err) {
    const cached = await caches.match(request);
    if (cached) return cached;
    return new Response(JSON.stringify({ error: 'Offline' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// ========================
// PUSH NOTIFICATIONS (Firebase ile birlikte çalışır)
// ========================
self.addEventListener('push', (event) => {
  if (!event.data) return;

  try {
    const data = event.data.json();
    const title = data.notification?.title || data.title || 'Women AI';
    const options = {
      body: data.notification?.body || data.body || '',
      icon: '/icons/icon-192.svg',
      badge: '/icons/icon-96.svg',
      tag: data.data?.tag || 'womenai-notification',
      data: data.data || {},
      vibrate: [200, 100, 200],
      actions: [
        { action: 'open', title: 'Aç' },
        { action: 'dismiss', title: 'Kapat' }
      ]
    };

    event.waitUntil(self.registration.showNotification(title, options));
  } catch (err) {
    console.error('SW: Push parse error:', err);
  }
});

// Bildirime tıklandığında
self.addEventListener('notificationclick', (event) => {
  event.notification.close();

  if (event.action === 'dismiss') return;

  const targetUrl = event.notification.data?.url || '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then(windowClients => {
        // Zaten açık pencere varsa fokusla
        for (const client of windowClients) {
          if (client.url.includes(self.location.origin) && 'focus' in client) {
            return client.focus();
          }
        }
        // Yoksa yeni pencere aç
        return clients.openWindow(targetUrl);
      })
  );
});

// ========================
// MESSAGE - Client'larla iletişim
// ========================
self.addEventListener('message', (event) => {
  if (event.data) {
    // Cache temizleme isteği
    if (event.data.type === 'CLEAR_CACHE') {
      caches.keys().then(keys => {
        keys.forEach(key => caches.delete(key));
      });
    }
    
    // Cache güncelleme isteği (yeni versiyon deploy sonrası)
    if (event.data.type === 'UPDATE_CACHE') {
      caches.open(STATIC_CACHE).then(cache => {
        cache.addAll(STATIC_ASSETS);
      });
    }

    // Firebase config forwarding (firebase-messaging-sw.js ile uyum)
    if (event.data.type === 'FIREBASE_CONFIG') {
      // Firebase SW'ye yönlendir
    }
  }
});
