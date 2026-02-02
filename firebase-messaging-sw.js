// Firebase Messaging Service Worker
// Push bildirimleri için arka planda çalışır

importScripts('https://www.gstatic.com/firebasejs/10.7.1/firebase-app-compat.js');
importScripts('https://www.gstatic.com/firebasejs/10.7.1/firebase-messaging-compat.js');

// Firebase config - server'dan alınacak
let firebaseConfig = null;

// Config'i almak için fetch kullanamayız SW'de, message ile alacağız
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'FIREBASE_CONFIG') {
    firebaseConfig = event.data.config;
    initializeFirebase();
  }
});

function initializeFirebase() {
  if (!firebaseConfig) return;
  
  firebase.initializeApp(firebaseConfig);
  const messaging = firebase.messaging();

  // Arka planda gelen bildirimler
  messaging.onBackgroundMessage((payload) => {
    console.log('📬 Arka plan bildirimi:', payload);

    const notificationTitle = payload.notification?.title || 'Women AI';
    const notificationOptions = {
      body: payload.notification?.body || 'Yeni bir bildiriminiz var',
      icon: '/favicon.svg',
      badge: '/favicon.svg',
      tag: payload.data?.tag || 'default',
      data: payload.data,
      vibrate: [200, 100, 200],
      actions: [
        { action: 'open', title: 'Aç' },
        { action: 'close', title: 'Kapat' }
      ]
    };

    self.registration.showNotification(notificationTitle, notificationOptions);
  });
}

// Bildirime tıklama
self.addEventListener('notificationclick', (event) => {
  console.log('🔔 Bildirime tıklandı:', event.notification.tag);
  
  event.notification.close();

  if (event.action === 'close') return;

  // Uygulamayı aç veya odaklan
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      // Açık pencere varsa odaklan
      for (const client of clientList) {
        if (client.url.includes('womenai') && 'focus' in client) {
          return client.focus();
        }
      }
      // Yoksa yeni pencere aç
      if (clients.openWindow) {
        return clients.openWindow('/');
      }
    })
  );
});

// Service Worker yükleme
self.addEventListener('install', (event) => {
  console.log('🔧 Push SW yüklendi');
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  console.log('✅ Push SW aktif');
  event.waitUntil(clients.claim());
});
