/**
 * Women AI Chat - Main JavaScript
 * Professional ChatGPT-style interface
 * Domain: womenai.semihcankadioglu.com.tr
 */

// Configuration
const API_URL = '/api/chat';
const WEATHER_URL = '/api/weather';
const GOOGLE_CLIENT_ID = ''; // .env'den alınacak, başlangıçta boş

// ========================================
// GOOGLE ANALYTICS 4 - EVENT TRACKING
// ========================================
function trackEvent(eventName, params = {}) {
  try {
    if (typeof gtag === 'function') {
      gtag('event', eventName, params);
    }
  } catch (e) {
    // GA4 yüklenemezse sessizce devam et
  }
}

// ========================================
// i18n - ÇOK DİLLİ DESTEK SİSTEMİ
// ========================================
const I18n = (() => {
  let currentLang = 'tr';
  let translations = {};
  let loaded = false;
  const supportedLangs = ['tr', 'en', 'zh'];
  const langLabels = { tr: 'Türkçe', en: 'English', zh: '中文' };

  // Nested key erişimi: t('survey.title') => translations.survey.title
  function getNestedValue(obj, path) {
    return path.split('.').reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : null), obj);
  }

  // Dil dosyasını yükle
  async function loadLanguage(lang) {
    if (!supportedLangs.includes(lang)) lang = 'tr';
    try {
      const res = await fetch(`/lang/${lang}.json?v=${Date.now()}`);
      if (!res.ok) throw new Error('Dil dosyası yüklenemedi');
      translations = await res.json();
      currentLang = lang;
      loaded = true;
      localStorage.setItem('womenai_lang', lang);
      document.documentElement.setAttribute('lang', lang);
    } catch (err) {
      console.error(`❌ Dil yüklenemedi (${lang}):`, err);
      if (lang !== 'tr') {
        // Fallback: Türkçe'ye dön
        await loadLanguage('tr');
      }
    }
  }

  // Çeviri al - t('login.title') veya t('survey.stepLabel', {current: 1, total: 4})
  function t(key, params) {
    const value = getNestedValue(translations, key);
    if (value === null || value === undefined) return key;
    if (typeof value !== 'string') return value;
    if (!params) return value;
    // {current} {total} gibi placeholder'ları değiştir
    return value.replace(/\{(\w+)\}/g, (_, k) => (params[k] !== undefined ? params[k] : `{${k}}`));
  }

  // DOM'daki tüm data-i18n elementlerini güncelle
  function applyTranslations() {
    // data-i18n: textContent değiştir
    document.querySelectorAll('[data-i18n]').forEach(el => {
      const key = el.getAttribute('data-i18n');
      const val = t(key);
      if (val && val !== key) el.textContent = val;
    });

    // data-i18n-placeholder: placeholder değiştir
    document.querySelectorAll('[data-i18n-placeholder]').forEach(el => {
      const key = el.getAttribute('data-i18n-placeholder');
      const val = t(key);
      if (val && val !== key) el.placeholder = val;
    });

    // data-i18n-title: title/aria-label değiştir
    document.querySelectorAll('[data-i18n-title]').forEach(el => {
      const key = el.getAttribute('data-i18n-title');
      const val = t(key);
      if (val && val !== key) {
        el.title = val;
        el.setAttribute('aria-label', val);
      }
    });

    // data-i18n-html: innerHTML değiştir
    document.querySelectorAll('[data-i18n-html]').forEach(el => {
      const key = el.getAttribute('data-i18n-html');
      const val = t(key);
      if (val && val !== key) el.innerHTML = val;
    });

    // Quick action data-prompt güncelle
    document.querySelectorAll('.quick-action-btn').forEach(btn => {
      const promptKey = btn.getAttribute('data-i18n-prompt');
      if (promptKey) {
        const val = t(promptKey);
        if (val && val !== promptKey) btn.setAttribute('data-prompt', val);
      }
    });

    // Page title güncelle
    const title = t('meta.title');
    if (title && title !== 'meta.title') document.title = title;
  }

  // Dil değiştir
  async function setLanguage(lang) {
    await loadLanguage(lang);
    applyTranslations();
    // Dil seçici UI güncelle
    updateLangSelector();
    // Custom event yayınla
    window.dispatchEvent(new CustomEvent('languageChanged', { detail: { lang } }));
  }

  function updateLangSelector() {
    // Flag buttons active state güncelle
    document.querySelectorAll('.lang-flag').forEach(flag => {
      flag.classList.toggle('active', flag.dataset.lang === currentLang);
    });
  }

  // Başlat
  async function init() {
    const saved = localStorage.getItem('womenai_lang');
    const lang = saved && supportedLangs.includes(saved) ? saved : 'tr';
    await loadLanguage(lang);
    applyTranslations();
    updateLangSelector();
  }

  return {
    init,
    t,
    setLanguage,
    applyTranslations,
    get currentLang() { return currentLang; },
    get supportedLangs() { return supportedLangs; },
    get langLabels() { return langLabels; },
    get loaded() { return loaded; },
  };
})();

// Kısa erişim
function t(key, params) { return I18n.t(key, params); }

// ========================================
// KULLANICI DAVRANIŞI TAKİP SİSTEMİ
// ========================================
const BehaviorTracker = (() => {
  let sessionId = null;
  let sessionStart = null;
  let eventQueue = [];
  let flushTimer = null;
  let currentPage = 'chat';
  let pageEnterTime = Date.now();
  let isActive = true;
  let totalActiveTime = 0;
  let lastActiveTime = Date.now();

  // Session ID oluştur
  function getSessionId() {
    if (!sessionId) {
      sessionId = 'ses_' + Date.now() + '_' + Math.random().toString(36).substr(2, 6);
      sessionStart = Date.now();
    }
    return sessionId;
  }

  // Cihaz bilgisi
  function getDeviceInfo() {
    const ua = navigator.userAgent;
    let deviceType = 'desktop';
    if (/Mobi|Android/i.test(ua)) deviceType = 'mobile';
    else if (/Tablet|iPad/i.test(ua)) deviceType = 'tablet';

    let browser = 'other';
    if (ua.includes('Chrome') && !ua.includes('Edg')) browser = 'chrome';
    else if (ua.includes('Safari') && !ua.includes('Chrome')) browser = 'safari';
    else if (ua.includes('Firefox')) browser = 'firefox';
    else if (ua.includes('Edg')) browser = 'edge';

    return {
      type: deviceType,
      browser,
      screenWidth: window.screen.width,
      screenHeight: window.screen.height,
    };
  }

  // Event'i kuyruğa ekle
  function log(event, category = 'interaction', data = {}) {
    eventQueue.push({
      event,
      category,
      data,
      page: currentPage,
      timestamp: Date.now(),
    });

    // GA4'e de gönder
    trackEvent(event, { category, page: currentPage, ...data });

    // 10 event birikince veya 30 sn sonra flush
    if (eventQueue.length >= 10) {
      flush();
    } else if (!flushTimer) {
      flushTimer = setTimeout(flush, 30000);
    }
  }

  // Kuyruğu sunucuya gönder
  async function flush() {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }

    if (eventQueue.length === 0) return;

    const batch = [...eventQueue];
    eventQueue = [];

    try {
      await fetch('/api/activity', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          events: batch,
          sessionId: getSessionId(),
          userId: getUserId(),
          device: getDeviceInfo(),
        }),
      });
    } catch (e) {
      // Başarısızsa kuyruğa geri koy (max 100 event)
      eventQueue = [...batch.slice(-50), ...eventQueue].slice(0, 100);
    }
  }

  // Sayfa/ekran değişimini takip et
  function trackPageView(page) {
    const now = Date.now();
    // Önceki sayfada geçen süre
    if (currentPage) {
      log('page_duration', 'engagement', {
        page: currentPage,
        duration: now - pageEnterTime,
      });
    }
    currentPage = page;
    pageEnterTime = now;
    log('page_view', 'navigation', { page });
  }

  // Aktiflik takibi
  function trackActivity() {
    // Kullanıcı ayrıldığında
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) {
        isActive = false;
        totalActiveTime += Date.now() - lastActiveTime;
        log('tab_hidden', 'engagement', { activeTime: totalActiveTime });
      } else {
        isActive = true;
        lastActiveTime = Date.now();
        log('tab_visible', 'engagement');
      }
    });

    // Sayfa kapanırken session_end gönder
    window.addEventListener('beforeunload', () => {
      if (!isActive) {
        totalActiveTime += 0;
      } else {
        totalActiveTime += Date.now() - lastActiveTime;
      }

      const sessionDuration = Date.now() - (sessionStart || Date.now());

      // sendBeacon ile garanti gönderim
      const payload = JSON.stringify({
        events: [{
          event: 'session_end',
          category: 'engagement',
          data: {
            sessionDuration,
            activeTime: totalActiveTime,
            pageCount: 0,
          },
          page: currentPage,
          duration: sessionDuration,
          timestamp: Date.now(),
        }],
        sessionId: getSessionId(),
        userId: getUserId(),
        device: getDeviceInfo(),
      });

      navigator.sendBeacon('/api/activity', new Blob([payload], { type: 'application/json' }));
    });
  }

  // Scroll derinliği takibi
  function trackScrollDepth() {
    let maxScroll = 0;
    const chatMessages = document.getElementById('chat-messages');
    if (!chatMessages) return;

    chatMessages.addEventListener('scroll', () => {
      const scrollPercent = Math.round(
        (chatMessages.scrollTop / (chatMessages.scrollHeight - chatMessages.clientHeight || 1)) * 100
      );
      if (scrollPercent > maxScroll + 25) { // Her %25'te bir logla
        maxScroll = scrollPercent;
        log('scroll_depth', 'engagement', { depth: maxScroll });
      }
    });
  }

  // Feature kullanım takibi
  function trackFeatureUsage(feature, data = {}) {
    log('feature_use', 'feature', { feature, ...data });
  }

  // Hata takibi
  function trackError(errorType, details = {}) {
    log('client_error', 'error', { errorType, ...details });
  }

  // Başlat
  function init() {
    getSessionId();
    log('session_start', 'engagement', {
      referrer: document.referrer || 'direct',
      url: window.location.href,
    });
    trackActivity();
    trackScrollDepth();

    // Periyodik flush (60 sn)
    setInterval(flush, 60000);
  }

  return {
    init,
    log,
    flush,
    trackPageView,
    trackFeatureUsage,
    trackError,
    getSessionId,
  };
})();

// State
let currentChatId = null;
let messages = [];
let currentMode = 'care';
let currentUser = null; // Giriş yapmış kullanıcı

// ========================================
// USER ID MANAGEMENT (Visitor Tracking + Google Auth)
// ========================================
function getUserId() {
  // Eğer Google ile giriş yapılmışsa
  if (currentUser && currentUser.id) {
    return `google_${currentUser.id}`;
  }
  
  // Misafir kullanıcı için visitor ID
  let visitorId = localStorage.getItem('womenai_visitor_id');
  if (!visitorId) {
    // Generate unique visitor ID
    visitorId = 'visitor_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    localStorage.setItem('womenai_visitor_id', visitorId);
  }
  return visitorId;
}

// ========================================
// GOOGLE AUTH MANAGEMENT
// ========================================
let isGoogleSignInProgress = false; // Çoklu tıklama koruması
let googleClientId = null; // Client ID'yi sakla

// Google popup ile giriş yap (One Tap çalışmazsa fallback)
function openGoogleSignInPopup() {
  if (!googleClientId) {
    alert(t('common.googleLoadError'));
    return;
  }
  
  const redirectUri = window.location.origin + '/auth/google/callback';
  
  const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?` +
    `client_id=${googleClientId}&` +
    `redirect_uri=${encodeURIComponent(redirectUri)}&` +
    `response_type=code&` +
    `scope=${encodeURIComponent('openid email profile')}&` +
    `prompt=select_account`;
  
  // Mobil cihaz tespiti
  const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
  
  if (isMobile) {
    // Mobilde aynı pencerede redirect yap (popup'lar sorunlu)
    window.location.href = authUrl;
  } else {
    // Desktop'ta popup aç
    const width = 500;
    const height = 600;
    const left = (window.innerWidth - width) / 2;
    const top = (window.innerHeight - height) / 2;
    
    window.open(authUrl, 'Google Sign In', 
      `width=${width},height=${height},left=${left},top=${top}`);
  }
}

async function handleGoogleSignIn(response) {
  if (isGoogleSignInProgress) {
    console.log('⏳ Giriş işlemi zaten devam ediyor...');
    return;
  }
  
  isGoogleSignInProgress = true;
  
  // Butonları devre dışı bırak
  const loginBtns = document.querySelectorAll('.google-login-btn-large, .google-login-btn');
  loginBtns.forEach(btn => {
    btn.disabled = true;
    btn.style.opacity = '0.6';
    btn.style.pointerEvents = 'none';
  });
  
  try {
    const res = await fetch('/api/auth/google', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ credential: response.credential }),
    });

    const data = await res.json();
    
    if (data.success && data.user) {
      currentUser = data.user;
      localStorage.setItem('womenai_user', JSON.stringify(data.user));
      
      // Eski sohbetleri Google hesabına taşı
      const oldVisitorId = localStorage.getItem('womenai_visitor_id');
      if (oldVisitorId) {
        await migrateChatsToGoogleAccount(oldVisitorId, data.user.id);
      }
      
      updateUserUI();
      updateLoginState(); // Chat alanını göster
      await loadChatHistory(); // Sohbetleri yeniden yükle
      await startNewChat(); // Yeni sohbet başlat
      trackEvent('login', { method: 'google' });
      BehaviorTracker.log('login', 'feature', { method: 'google', userName: data.user.name });
      
      // GA4 kullanıcı özelliklerini ayarla
      if (typeof gtag === 'function') {
        gtag('set', 'user_properties', {
          user_type: 'google',
          has_profile: data.user.profile?.isProfileComplete ? 'yes' : 'no',
          skin_type: data.user.profile?.skinType || 'unknown',
        });
        gtag('config', 'G-EV7WSFQLQD', { user_id: data.user.id });
      }
      
      console.log('✅ Google ile giriş başarılı:', data.user.name);
    } else {
      console.error('Google giriş hatası:', data.error);
      alert(t('common.loginFailed') + ': ' + (data.error || ''));
    }
  } catch (err) {
    console.error('Google auth error:', err);
    alert(t('common.loginError'));
  } finally {
    isGoogleSignInProgress = false;
    // Butonları tekrar aktif et
    loginBtns.forEach(btn => {
      btn.disabled = false;
      btn.style.opacity = '1';
      btn.style.pointerEvents = 'auto';
    });
  }
}

async function migrateChatsToGoogleAccount(visitorId, googleUserId) {
  try {
    const res = await fetch('/api/auth/migrate-chats', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ visitorId, googleUserId }),
    });
    
    const data = await res.json();
    if (data.success && data.migratedCount > 0) {
      console.log(`✅ ${data.migratedCount} sohbet Google hesabına taşındı`);
    }
  } catch (err) {
    console.error('Chat migration error:', err);
  }
}

function handleGoogleSignOut() {
  currentUser = null;
  localStorage.removeItem('womenai_user');
  console.log('✅ Çıkış yapıldı');
  
  // Sayfayı yenile - Google Sign-In'i resetlemek için
  window.location.reload();
}

// Giriş durumuna göre ekranları göster/gizle
function updateLoginState() {
  const loginScreen = document.getElementById('login-screen');
  const chatContainer = document.getElementById('chat-container');
  const sidebar = document.getElementById('sidebar');
  const mobileMenuToggle = document.getElementById('mobile-menu-toggle');
  const mainContent = document.querySelector('.main-content');
  const inputContainer = document.querySelector('.input-container');

  console.log('🔄 updateLoginState called, currentUser:', currentUser ? currentUser.name : 'null');
  console.log('🔄 DOM elements:', {
    loginScreen: !!loginScreen,
    chatContainer: !!chatContainer,
    sidebar: !!sidebar,
    mainContent: !!mainContent,
    inputContainer: !!inputContainer
  });

  if (currentUser) {
    // Giriş yapılmış - chat alanını göster
    console.log('✅ Showing chat, hiding login screen');
    if (loginScreen) {
      loginScreen.style.display = 'none';
      loginScreen.style.visibility = 'hidden';
      loginScreen.style.position = 'absolute';
      loginScreen.style.pointerEvents = 'none';
    }
    if (chatContainer) chatContainer.style.display = 'flex';
    if (sidebar) sidebar.classList.remove('login-required');
    if (mobileMenuToggle) {
      mobileMenuToggle.classList.remove('hidden');
    }
    if (mainContent) mainContent.classList.remove('login-active');
    if (inputContainer) inputContainer.style.display = 'block';
  } else {
    // Giriş yapılmamış - login ekranını göster
    console.log('❌ Showing login screen, hiding chat');
    if (loginScreen) {
      loginScreen.style.display = 'flex';
      loginScreen.style.visibility = 'visible';
      loginScreen.style.position = 'relative';
      loginScreen.style.pointerEvents = 'auto';
    }
    if (chatContainer) chatContainer.style.display = 'none';
    if (sidebar) sidebar.classList.add('login-required');
    if (mobileMenuToggle) {
      mobileMenuToggle.classList.add('hidden');
    }
    if (mainContent) mainContent.classList.add('login-active');
    if (inputContainer) inputContainer.style.display = 'none';
  }
}

function updateUserUI() {
  const userGuest = document.getElementById('user-guest');
  const userProfile = document.getElementById('user-profile');
  const userAvatar = document.getElementById('user-avatar');
  const userName = document.getElementById('user-name');
  const userEmail = document.getElementById('user-email');

  if (currentUser) {
    // Giriş yapmış kullanıcı
    if (userGuest) userGuest.style.display = 'none';
    if (userProfile) userProfile.style.display = 'flex';
    // Default avatar - data URI SVG
    const defaultAvatar = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0iI0M0NUM3QyI+PGNpcmNsZSBjeD0iMjAiIGN5PSIxNSIgcj0iOCIgZmlsbD0iI0U4QTBCNSIvPjxwYXRoIGQ9Ik0zNSAzOGMwLTguMjg0LTYuNzE2LTE1LTE1LTE1cy0xNSA2LjcxNi0xNSAxNSIgZmlsbD0iI0U4QTBCNSIvPjwvc3ZnPg==';
    
    // Avatar URL'sini doğrula - sadece güvenilir kaynaklardan gelen URL'leri kabul et
    const isValidAvatarUrl = (url) => {
      if (!url || typeof url !== 'string') return false;
      // Google ve diğer güvenilir kaynakları kabul et
      const trustedDomains = ['googleusercontent.com', 'google.com', 'gstatic.com', 'gravatar.com'];
      try {
        const urlObj = new URL(url);
        return trustedDomains.some(domain => urlObj.hostname.endsWith(domain));
      } catch {
        return false;
      }
    };
    
    const avatarUrl = isValidAvatarUrl(currentUser.picture) ? currentUser.picture : defaultAvatar;
    if (userAvatar) userAvatar.src = avatarUrl;
    if (userName) userName.textContent = currentUser.name || t('profile.user');
    if (userEmail) userEmail.textContent = currentUser.email || '';
  } else {
    // Misafir kullanıcı
    if (userGuest) userGuest.style.display = 'block';
    if (userProfile) userProfile.style.display = 'none';
  }
}

async function initGoogleAuth() {
  // URL'den auth bilgisini kontrol et (OAuth callback'ten redirect)
  const urlParams = new URLSearchParams(window.location.search);
  const authData = urlParams.get('auth_success');
  
  console.log('🔍 initGoogleAuth: URL params:', window.location.search);
  console.log('🔍 initGoogleAuth: authData:', authData ? authData.substring(0, 30) + '...' : 'null');
  
  if (authData) {
    try {
      // URL-safe base64'ü normal base64'e çevir
      const base64 = authData.replace(/-/g, '+').replace(/_/g, '/');
      const padding = base64.length % 4;
      const paddedBase64 = padding ? base64 + '='.repeat(4 - padding) : base64;
      
      console.log('🔍 Decoding base64...');
      const userData = JSON.parse(atob(paddedBase64));
      console.log('✅ userData parsed:', userData);
      
      currentUser = userData;
      localStorage.setItem('womenai_user', JSON.stringify(userData));
      
      // URL'den auth parametresini temizle
      window.history.replaceState({}, document.title, window.location.pathname);
      
      console.log('✅ OAuth ile giriş başarılı:', userData.name);
      updateUserUI();
      updateLoginState();
      
      // Sohbetleri yükle
      await loadChatHistory();
      await startNewChat();
      
      return true; // OAuth ile giriş yapıldı ve chat yüklendi
    } catch (e) {
      console.error('❌ Auth data parse error:', e);
    }
  }
  
  // Local storage'dan kullanıcıyı yükle
  const savedUser = localStorage.getItem('womenai_user');
  console.log('🔍 savedUser from localStorage:', savedUser ? 'EXISTS' : 'NULL');
  
  if (savedUser) {
    try {
      currentUser = JSON.parse(savedUser);
      console.log('✅ User loaded from localStorage:', currentUser.name);
      updateUserUI();
      updateLoginState();
    } catch (e) {
      localStorage.removeItem('womenai_user');
      updateLoginState();
    }
  } else {
    updateLoginState();
  }

  // Google Sign-In butonu event listener (sidebar'daki)
  const googleLoginBtn = document.getElementById('google-login-btn');
  if (googleLoginBtn) {
    googleLoginBtn.addEventListener('click', (e) => {
      e.preventDefault();
      if (isGoogleSignInProgress) return;
      
      // Popup ile giriş yap (One Tap cooldown sorununu çözer)
      openGoogleSignInPopup();
    });
  }

  // Ana giriş ekranındaki Google butonu
  const googleLoginBtnMain = document.getElementById('google-login-btn-main');
  if (googleLoginBtnMain) {
    googleLoginBtnMain.addEventListener('click', (e) => {
      e.preventDefault();
      if (isGoogleSignInProgress) return;
      
      // Popup ile giriş yap
      openGoogleSignInPopup();
    });
  }

  // Çıkış butonu
  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) {
    logoutBtn.addEventListener('click', handleGoogleSignOut);
  }

  // Google Identity Services'ı initialize et
  fetchGoogleClientId();
  return false; // OAuth callback değil, chat yüklenmedi
}

async function fetchGoogleClientId() {
  try {
    // Server'dan config al
    const response = await fetch('/api/config');
    const config = await response.json();
    const clientId = config.googleClientId;
    
    // Client ID'yi global değişkene kaydet (popup için)
    googleClientId = clientId;
    
    if (clientId && window.google && window.google.accounts) {
      google.accounts.id.initialize({
        client_id: clientId,
        callback: handleGoogleSignIn,
        auto_select: false,
        cancel_on_tap_outside: true,
      });
      console.log('✅ Google Sign-In hazır');
    } else if (!clientId) {
      console.warn('⚠️ Google Client ID yapılandırılmamış');
    }

    // Firebase Push Notification başlat
    if (config.firebase && config.firebase.apiKey) {
      await initPushNotifications(config);
    }
  } catch (err) {
    console.error('Config alınamadı:', err);
  }
}

// ========================================
// PUSH NOTIFICATIONS
// ========================================
let fcmToken = null;
let pushEnabled = false;

async function initPushNotifications(config) {
  try {
    // Service Worker'ı kaydet
    if (!('serviceWorker' in navigator)) {
      console.warn('⚠️ Service Worker desteklenmiyor');
      return;
    }

    if (!('PushManager' in window)) {
      console.warn('⚠️ Push bildirimleri desteklenmiyor');
      return;
    }

    // Firebase initialize
    if (!firebase.apps.length) {
      firebase.initializeApp(config.firebase);
    }
    
    const messaging = firebase.messaging();

    // Service Worker kaydet
    const registration = await navigator.serviceWorker.register('/firebase-messaging-sw.js');
    console.log('✅ Push SW kaydedildi');

    // SW'ye Firebase config gönder
    if (registration.active) {
      registration.active.postMessage({
        type: 'FIREBASE_CONFIG',
        config: config.firebase
      });
    }

    // Mevcut izin durumunu kontrol et
    const permission = Notification.permission;
    
    if (permission === 'granted') {
      // İzin zaten var, token al
      await getAndSaveToken(messaging, config.vapidKey, registration);
    } else if (permission === 'default') {
      // İzin henüz sorulmamış, UI göster
      showNotificationPrompt();
    }

    // Ön plandayken gelen mesajları dinle
    messaging.onMessage((payload) => {
      console.log('📬 Ön plan bildirimi:', payload);
      
      // Custom bildirim göster
      showInAppNotification(payload.notification?.title, payload.notification?.body);
    });

    console.log('✅ Push Notifications hazır');
  } catch (err) {
    console.error('Push init error:', err);
  }
}

async function getAndSaveToken(messaging, vapidKey, registration) {
  try {
    fcmToken = await messaging.getToken({
      vapidKey: vapidKey,
      serviceWorkerRegistration: registration
    });

    if (fcmToken) {
      console.log('✅ FCM Token alındı');
      pushEnabled = true;
      
      // Token'ı server'a kaydet
      await fetch('/api/push/subscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: getUserId(),
          fcmToken: fcmToken,
        }),
      });

      // UI güncelle
      updateNotificationUI(true);
    }
  } catch (err) {
    console.error('Token alınamadı:', err);
  }
}

async function requestNotificationPermission() {
  try {
    const permission = await Notification.requestPermission();
    
    if (permission === 'granted') {
      console.log('✅ Bildirim izni verildi');
      trackEvent('push_permission', { status: 'granted' });
      
      // Config'i tekrar al ve token al
      const response = await fetch('/api/config');
      const config = await response.json();
      
      if (config.firebase && config.firebase.apiKey) {
        const messaging = firebase.messaging();
        const registration = await navigator.serviceWorker.ready;
        await getAndSaveToken(messaging, config.vapidKey, registration);
      }
      
      hideNotificationPrompt();
    } else {
      console.log('❌ Bildirim izni reddedildi');
      hideNotificationPrompt();
    }
  } catch (err) {
    console.error('İzin hatası:', err);
  }
}

async function disableNotifications() {
  try {
    if (fcmToken) {
      await fetch('/api/push/unsubscribe', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ fcmToken }),
      });
    }
    
    pushEnabled = false;
    fcmToken = null;
    updateNotificationUI(false);
    console.log('✅ Bildirimler kapatıldı');
  } catch (err) {
    console.error('Bildirim kapatma hatası:', err);
  }
}

function showNotificationPrompt() {
  // Bildirim izni isteme UI'ı göster
  const prompt = document.getElementById('notification-prompt');
  if (prompt) {
    prompt.style.display = 'flex';
  }
}

function hideNotificationPrompt() {
  const prompt = document.getElementById('notification-prompt');
  if (prompt) {
    prompt.style.display = 'none';
  }
}

function updateNotificationUI(enabled) {
  // Sidebar'daki bildirim butonlarını güncelle
  document.querySelectorAll('.notification-toggle-btn').forEach(btn => {
    btn.textContent = enabled ? t('notification.on') : t('notification.off');
    btn.classList.toggle('active', enabled);
  });
  
  // Reminder settings'i göster/gizle
  const reminderSettings = document.getElementById('reminder-settings');
  if (reminderSettings) {
    reminderSettings.style.display = (enabled && currentUser) ? 'block' : 'none';
    if (enabled && currentUser) {
      loadReminderSettings();
    }
  }
}

// ========================================
// REMINDER SETTINGS (Hatırlatıcı Ayarları)
// ========================================
async function loadReminderSettings() {
  if (!fcmToken) return;
  
  try {
    const response = await fetch(`/api/push/preferences?fcmToken=${encodeURIComponent(fcmToken)}`);
    if (response.ok) {
      const data = await response.json();
      
      // Skincare toggle ve zamanları ayarla
      const skincareToggle = document.getElementById('skincare-reminder-toggle');
      const skincareTimes = document.getElementById('skincare-times');
      const morningTime = document.getElementById('skincare-morning-time');
      const eveningTime = document.getElementById('skincare-evening-time');
      
      if (skincareToggle) {
        skincareToggle.checked = data.preferences?.skincare || false;
        if (skincareTimes) {
          skincareTimes.classList.toggle('hidden', !skincareToggle.checked);
        }
      }
      if (morningTime) morningTime.value = data.reminderTimes?.morning || '07:00';
      if (eveningTime) eveningTime.value = data.reminderTimes?.evening || '21:00';
      
      // Water toggle ve interval ayarla
      const waterToggle = document.getElementById('water-reminder-toggle');
      const waterTimes = document.getElementById('water-times');
      const waterInterval = document.getElementById('water-interval');
      
      if (waterToggle) {
        waterToggle.checked = data.preferences?.water || false;
        if (waterTimes) {
          waterTimes.classList.toggle('hidden', !waterToggle.checked);
        }
      }
      if (waterInterval) waterInterval.value = data.reminderTimes?.waterInterval || 2;
      
      console.log('✅ Hatırlatıcı ayarları yüklendi');
    }
  } catch (err) {
    console.error('Hatırlatıcı ayarları yükleme hatası:', err);
  }
}

async function saveReminderSettings() {
  if (!fcmToken) {
    showInAppNotification(t('common.error'), t('common.enableNotifFirst'));
    return;
  }
  
  const saveBtn = document.getElementById('save-reminder-settings');
  if (saveBtn) {
    saveBtn.disabled = true;
    saveBtn.textContent = '⏳ ' + t('survey.saving').replace('⏳ ', '');
  }
  
  try {
    const preferences = {
      skincare: document.getElementById('skincare-reminder-toggle')?.checked || false,
      water: document.getElementById('water-reminder-toggle')?.checked || false
    };
    
    const reminderTimes = {
      morning: document.getElementById('skincare-morning-time')?.value || '07:00',
      evening: document.getElementById('skincare-evening-time')?.value || '21:00',
      waterInterval: parseInt(document.getElementById('water-interval')?.value) || 2
    };
    
    const response = await fetch('/api/push/preferences', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        fcmToken,
        preferences,
        reminderTimes
      })
    });
    
    if (response.ok) {
      showInAppNotification(t('reminder.saved'), t('reminder.savedDesc'));
      console.log('✅ Hatırlatıcı ayarları kaydedildi');
    } else {
      throw new Error('Kayıt başarısız');
    }
  } catch (err) {
    console.error('Hatırlatıcı kaydetme hatası:', err);
    showInAppNotification('❌ ' + t('common.error'), t('reminder.saveFailed'));
  } finally {
    if (saveBtn) {
      saveBtn.disabled = false;
      saveBtn.textContent = t('reminder.save');
    }
  }
}

function initReminderSettings() {
  // Skincare toggle
  const skincareToggle = document.getElementById('skincare-reminder-toggle');
  const skincareTimes = document.getElementById('skincare-times');
  if (skincareToggle && skincareTimes) {
    skincareToggle.addEventListener('change', () => {
      skincareTimes.classList.toggle('hidden', !skincareToggle.checked);
    });
  }
  
  // Water toggle
  const waterToggle = document.getElementById('water-reminder-toggle');
  const waterTimes = document.getElementById('water-times');
  if (waterToggle && waterTimes) {
    waterToggle.addEventListener('change', () => {
      waterTimes.classList.toggle('hidden', !waterToggle.checked);
    });
  }
  
  // Save button
  const saveBtn = document.getElementById('save-reminder-settings');
  if (saveBtn) {
    saveBtn.addEventListener('click', saveReminderSettings);
  }
}

// ========================================
// PROFILE PAGE (Kullanıcı Profil Sayfası)
// ========================================
function openProfileModal() {
  if (!currentUser) return;
  BehaviorTracker.trackPageView('profile');
  
  const overlay = document.getElementById('profile-modal-overlay');
  if (!overlay) return;
  
  // Profil bilgilerini doldur
  const profileAvatar = document.getElementById('profile-avatar');
  const profileName = document.getElementById('profile-name');
  const profileEmail = document.getElementById('profile-email');
  
  if (profileAvatar) {
    const defaultAvatar = 'data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCA0MCA0MCIgZmlsbD0iI0M0NUM3QyI+PGNpcmNsZSBjeD0iMjAiIGN5PSIxNSIgcj0iOCIgZmlsbD0iI0U4QTBCNSIvPjxwYXRoIGQ9Ik0zNSAzOGMwLTguMjg0LTYuNzE2LTE1LTE1LTE1cy0xNSA2LjcxNi0xNSAxNSIgZmlsbD0iI0U4QTBCNSIvPjwvc3ZnPg==';
    const isValid = currentUser.picture && typeof currentUser.picture === 'string' && 
      ['googleusercontent.com', 'google.com', 'gstatic.com', 'gravatar.com'].some(d => {
        try { return new URL(currentUser.picture).hostname.endsWith(d); } catch { return false; }
      });
    profileAvatar.src = isValid ? currentUser.picture : defaultAvatar;
  }
  if (profileName) profileName.textContent = currentUser.name || t('profile.user');
  if (profileEmail) profileEmail.textContent = currentUser.email || '';
  
  // Bildirim durumu
  const profileNotifications = document.getElementById('profile-notifications');
  if (profileNotifications) {
    profileNotifications.textContent = pushEnabled ? t('profile.notifOn') : t('profile.notifOff');
  }
  
  // İstatistikleri yükle
  loadProfileStats();
  
  overlay.style.display = 'flex';
}

function closeProfileModal() {
  const overlay = document.getElementById('profile-modal-overlay');
  if (overlay) overlay.style.display = 'none';
}

async function loadProfileStats() {
  if (!currentUser) return;
  
  try {
    const userId = getUserId();
    
    // Sohbet istatistiklerini API'den al
    const response = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'list', userId })
    });
    
    if (response.ok) {
      const data = await response.json();
      const chats = data.chats || [];
      
      // Toplam sohbet sayısı
      const statChats = document.getElementById('profile-stat-chats');
      if (statChats) statChats.textContent = chats.length;
      
      // Toplam mesaj sayısı
      const totalMessages = chats.reduce((sum, c) => sum + (c.messageCount || 0), 0);
      const statMessages = document.getElementById('profile-stat-messages');
      if (statMessages) statMessages.textContent = totalMessages;
      
      // En çok kullanılan mod
      const modeCounts = {};
      chats.forEach(c => {
        const m = c.mode || 'care';
        modeCounts[m] = (modeCounts[m] || 0) + 1;
      });
      const modeNames = { care: t('mode.careFull'), motivation: t('mode.motivationFull'), diet: t('mode.dietFull') };
      const topMode = Object.keys(modeCounts).sort((a, b) => modeCounts[b] - modeCounts[a])[0];
      const favMode = document.getElementById('profile-fav-mode');
      if (favMode) favMode.textContent = topMode ? (modeNames[topMode] || topMode) : '-';
    }
    
    // Kullanıcı profil bilgilerini API'den al
    const userResponse = await fetch(`/api/auth/user/${currentUser.id}`);
    if (userResponse.ok) {
      const userData = await userResponse.json();
      
      // Üyelik tarihi
      const joinedEl = document.getElementById('profile-joined');
      if (joinedEl && userData.createdAt) {
        joinedEl.textContent = new Date(userData.createdAt).toLocaleDateString(I18n.currentLang === 'zh' ? 'zh-CN' : I18n.currentLang === 'en' ? 'en-US' : 'tr-TR', {
          day: 'numeric', month: 'long', year: 'numeric'
        });
      }
      
      // Son giriş (şimdiki zaman çünkü kullanıcı şu an aktif)
      const lastLoginEl = document.getElementById('profile-last-login');
      if (lastLoginEl) {
        lastLoginEl.textContent = new Date().toLocaleDateString(I18n.currentLang === 'zh' ? 'zh-CN' : I18n.currentLang === 'en' ? 'en-US' : 'tr-TR', {
          day: 'numeric', month: 'long', year: 'numeric', hour: '2-digit', minute: '2-digit'
        });
      }
      
      // Üyelik süresi (gün)
      const statDays = document.getElementById('profile-stat-days');
      if (statDays && userData.createdAt) {
        const days = Math.floor((Date.now() - new Date(userData.createdAt).getTime()) / (1000 * 60 * 60 * 24));
        statDays.textContent = Math.max(1, days);
      }
      
      // Profil anketi tamamlanmış mı?
      if (userData.profile && userData.profile.isProfileComplete) {
        updateSurveyButton(true);
      }
    }
    
  } catch (err) {
    console.error('Profil istatistik hatası:', err);
  }
}

function initProfilePage() {
  // User info tıklama -> profil aç
  const userInfoBtn = document.getElementById('user-info-btn');
  if (userInfoBtn) {
    userInfoBtn.addEventListener('click', openProfileModal);
  }
  
  // Kapatma butonu
  const closeBtn = document.getElementById('profile-modal-close');
  if (closeBtn) {
    closeBtn.addEventListener('click', closeProfileModal);
  }
  
  // Overlay tıklama (dışına tıklayınca kapat)
  const overlay = document.getElementById('profile-modal-overlay');
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeProfileModal();
    });
  }
  
  // Profil sayfasındaki çıkış butonu
  const profileLogoutBtn = document.getElementById('profile-logout-btn');
  if (profileLogoutBtn) {
    profileLogoutBtn.addEventListener('click', () => {
      closeProfileModal();
      // Mevcut logout fonksiyonunu çağır
      const logoutBtn = document.getElementById('logout-btn');
      if (logoutBtn) logoutBtn.click();
    });
  }
  
  // Anket butonu
  const openSurveyBtn = document.getElementById('open-survey-btn');
  if (openSurveyBtn) {
    openSurveyBtn.addEventListener('click', () => {
      closeProfileModal();
      openSurveyModal();
    });
  }
  
  // Anket modal init
  initSurveyModal();
}

// ========================================
// SURVEY MODAL (Profil Anketi)
// ========================================
let surveyStep = 1;
const TOTAL_STEPS = 4;

function openSurveyModal() {
  const overlay = document.getElementById('survey-modal-overlay');
  if (!overlay) return;
  BehaviorTracker.trackPageView('survey');
  
  surveyStep = 1;
  showSurveyStep(1);
  loadExistingSurveyData();
  overlay.style.display = 'flex';
}

function closeSurveyModal() {
  const overlay = document.getElementById('survey-modal-overlay');
  if (overlay) overlay.style.display = 'none';
}

function showSurveyStep(step) {
  surveyStep = step;
  
  // Tüm adımları gizle
  for (let i = 1; i <= TOTAL_STEPS; i++) {
    const el = document.getElementById(`survey-step-${i}`);
    if (el) el.style.display = i === step ? 'block' : 'none';
  }
  
  // Progress bar güncelle
  const bar = document.getElementById('survey-progress-bar');
  if (bar) bar.style.width = `${(step / TOTAL_STEPS) * 100}%`;
  
  // Step label güncelle
  const label = document.getElementById('survey-step-label');
  if (label) label.textContent = t('survey.stepLabel', { current: step, total: TOTAL_STEPS });
  
  // Butonları güncelle
  const prevBtn = document.getElementById('survey-prev-btn');
  const nextBtn = document.getElementById('survey-next-btn');
  if (prevBtn) prevBtn.style.display = step > 1 ? 'block' : 'none';
  if (nextBtn) {
    if (step === TOTAL_STEPS) {
      nextBtn.textContent = t('survey.saveBtn');
    } else {
      nextBtn.textContent = t('survey.nextBtn');
    }
  }
  
  // Son adımda özet göster
  if (step === TOTAL_STEPS) {
    buildSurveySummary();
  }
}

function getSurveyData() {
  // Cilt tipi
  const skinTypeEl = document.querySelector('input[name="skinType"]:checked');
  const skinType = skinTypeEl ? skinTypeEl.value : '';
  
  // Cilt sorunları
  const skinConcerns = Array.from(document.querySelectorAll('input[name="skinConcern"]:checked')).map(el => el.value);
  
  // Yaş
  const ageEl = document.querySelector('input[name="age"]:checked');
  const age = ageEl ? ageEl.value : '';
  
  // Cinsiyet
  const genderEl = document.querySelector('input[name="gender"]:checked');
  const gender = genderEl ? genderEl.value : '';
  
  // Bölge
  const region = document.getElementById('survey-region')?.value || '';
  
  // Alerjiler
  const allergies = Array.from(document.querySelectorAll('input[name="allergy"]:checked')).map(el => el.value);
  
  // Hassasiyetler
  const sensitivities = Array.from(document.querySelectorAll('input[name="sensitivity"]:checked')).map(el => el.value);
  
  return { skinType, skinConcerns, age, gender, region, allergies, sensitivities };
}

function buildSurveySummary() {
  const data = getSurveyData();
  const summary = document.getElementById('survey-summary');
  if (!summary) return;
  
  const skinTypeNames = { kuru: t('survey.skinDry'), yagli: t('survey.skinOily'), karma: t('survey.skinCombo'), normal: t('survey.skinNormal'), hassas: t('survey.skinSensitive') };
  const genderNames = { kadin: t('survey.female'), erkek: t('survey.male'), 'belirtmek-istemiyorum': t('survey.notSpecify') };
  
  let html = '';
  html += `<div class="survey-summary-item"><span class="survey-summary-label">${t('survey.summaryLabels.skinType')}</span><span class="survey-summary-value">${skinTypeNames[data.skinType] || '—'}</span></div>`;
  html += `<div class="survey-summary-item"><span class="survey-summary-label">${t('survey.summaryLabels.skinConcerns')}</span><span class="survey-summary-value">${data.skinConcerns.length > 0 ? data.skinConcerns.join(', ') : '—'}</span></div>`;
  html += `<div class="survey-summary-item"><span class="survey-summary-label">${t('survey.summaryLabels.ageRange')}</span><span class="survey-summary-value">${data.age || '—'}</span></div>`;
  html += `<div class="survey-summary-item"><span class="survey-summary-label">${t('survey.summaryLabels.gender')}</span><span class="survey-summary-value">${genderNames[data.gender] || '—'}</span></div>`;
  html += `<div class="survey-summary-item"><span class="survey-summary-label">${t('survey.summaryLabels.region')}</span><span class="survey-summary-value">${data.region || '—'}</span></div>`;
  html += `<div class="survey-summary-item"><span class="survey-summary-label">${t('survey.summaryLabels.allergies')}</span><span class="survey-summary-value">${data.allergies.length > 0 ? data.allergies.join(', ') : '—'}</span></div>`;
  html += `<div class="survey-summary-item"><span class="survey-summary-label">${t('survey.summaryLabels.sensitivities')}</span><span class="survey-summary-value">${data.sensitivities.length > 0 ? data.sensitivities.join(', ') : '—'}</span></div>`;
  
  summary.innerHTML = html;
}

async function saveSurveyData() {
  if (!currentUser) return;
  
  const nextBtn = document.getElementById('survey-next-btn');
  if (nextBtn) {
    nextBtn.disabled = true;
    nextBtn.textContent = t('survey.saving');
  }
  
  try {
    const data = getSurveyData();
    
    const response = await fetch('/api/user/profile', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        userId: currentUser.id,
        profile: data
      })
    });
    
    if (response.ok) {
      closeSurveyModal();
      showInAppNotification(t('common.profileSaved'), t('common.profileSavedDesc'));
      trackEvent('survey_complete', { skin_type: data.skinType, age: data.age, region: data.region });
      
      // Profil butonu güncelle
      updateSurveyButton(true);
    } else {
      throw new Error('Kayıt başarısız');
    }
  } catch (err) {
    console.error('Anket kayıt hatası:', err);
    showInAppNotification('❌ ' + t('common.error'), t('common.profileSaveFailed'));
  } finally {
    if (nextBtn) {
      nextBtn.disabled = false;
      nextBtn.textContent = t('survey.saveBtn');
    }
  }
}

async function loadExistingSurveyData() {
  if (!currentUser) return;
  
  try {
    const response = await fetch(`/api/user/profile/${currentUser.id}`);
    if (response.ok) {
      const data = await response.json();
      if (data.profile && data.isComplete) {
        const p = data.profile;
        
        // Radio'ları seç
        if (p.skinType) {
          const el = document.querySelector(`input[name="skinType"][value="${p.skinType}"]`);
          if (el) el.checked = true;
        }
        if (p.age) {
          const el = document.querySelector(`input[name="age"][value="${p.age}"]`);
          if (el) el.checked = true;
        }
        if (p.gender) {
          const el = document.querySelector(`input[name="gender"][value="${p.gender}"]`);
          if (el) el.checked = true;
        }
        
        // Checkboxları seç
        (p.skinConcerns || []).forEach(v => {
          const el = document.querySelector(`input[name="skinConcern"][value="${v}"]`);
          if (el) el.checked = true;
        });
        (p.allergies || []).forEach(v => {
          const el = document.querySelector(`input[name="allergy"][value="${v}"]`);
          if (el) el.checked = true;
        });
        (p.sensitivities || []).forEach(v => {
          const el = document.querySelector(`input[name="sensitivity"][value="${v}"]`);
          if (el) el.checked = true;
        });
        
        // Bölge
        if (p.region) {
          const region = document.getElementById('survey-region');
          if (region) region.value = p.region;
        }
      }
    }
  } catch (err) {
    console.log('Mevcut profil verisi yüklenemedi:', err.message);
  }
}

function updateSurveyButton(isComplete) {
  const btn = document.getElementById('open-survey-btn');
  const icon = document.getElementById('survey-btn-icon');
  const text = document.getElementById('survey-btn-text');
  const hint = document.getElementById('survey-hint');
  
  if (isComplete) {
    if (btn) btn.classList.add('completed');
    if (icon) icon.textContent = '✅';
    if (text) text.textContent = t('profile.surveyEdit');
    if (hint) hint.textContent = t('profile.surveyComplete');
  }
}

function initSurveyModal() {
  // Kapatma
  const closeBtn = document.getElementById('survey-modal-close');
  if (closeBtn) closeBtn.addEventListener('click', closeSurveyModal);
  
  // Overlay tıklama
  const overlay = document.getElementById('survey-modal-overlay');
  if (overlay) {
    overlay.addEventListener('click', (e) => {
      if (e.target === overlay) closeSurveyModal();
    });
  }
  
  // Geri butonu
  const prevBtn = document.getElementById('survey-prev-btn');
  if (prevBtn) {
    prevBtn.addEventListener('click', () => {
      if (surveyStep > 1) showSurveyStep(surveyStep - 1);
    });
  }
  
  // İleri butonu
  const nextBtn = document.getElementById('survey-next-btn');
  if (nextBtn) {
    nextBtn.addEventListener('click', () => {
      if (surveyStep < TOTAL_STEPS) {
        showSurveyStep(surveyStep + 1);
      } else {
        saveSurveyData();
      }
    });
  }
}

function showInAppNotification(title, body) {
  // Uygulama içi bildirim toast
  const toast = document.createElement('div');
  toast.className = 'notification-toast';
  toast.innerHTML = `
    <div class="notification-toast-icon">💜</div>
    <div class="notification-toast-content">
      <div class="notification-toast-title">${(title || 'Women AI').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
      <div class="notification-toast-body">${(body || '').replace(/</g, '&lt;').replace(/>/g, '&gt;')}</div>
    </div>
    <button class="notification-toast-close">&times;</button>
  `;
  
  document.body.appendChild(toast);
  
  // Animasyon ile göster
  setTimeout(() => toast.classList.add('show'), 10);
  
  // Kapatma butonu
  toast.querySelector('.notification-toast-close').addEventListener('click', () => {
    toast.classList.remove('show');
    setTimeout(() => toast.remove(), 300);
  });
  
  // 5 saniye sonra otomatik kapat
  setTimeout(() => {
    if (toast.parentNode) {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 300);
    }
  }, 5000);
}

// DOM Elements
const elements = {
  chatHistory: document.getElementById('chat-history'),
  chatMessages: document.getElementById('chat-messages'),
  chatInput: document.getElementById('chat-input'),
  sendBtn: document.getElementById('chat-send'),
  newChatBtn: document.getElementById('new-chat-btn'),
  clearHistoryBtn: document.getElementById('clear-history'),
  themeToggle: document.getElementById('theme-toggle'),
  welcomeScreen: document.getElementById('welcome-screen'),
  weatherCard: document.getElementById('weather-card'),
  weatherModalOverlay: document.getElementById('weather-modal-overlay'),
  weatherModalClose: document.getElementById('weather-modal-close'),
  weatherRefresh: document.getElementById('weather-refresh'),
  weatherStats: document.getElementById('weather-stats'),
  weatherAnalysisContent: document.getElementById('weather-analysis-content'),
  weatherLocation: document.getElementById('weather-location'),
  weatherDate: document.getElementById('weather-date'),
  weatherHeaderIcon: document.getElementById('weather-header-icon'),
  modeBtns: document.querySelectorAll('.mode-btn'),
  quickActionBtns: document.querySelectorAll('.quick-action-btn'),
  // Mobile elements
  mobileMenuToggle: document.getElementById('mobile-menu-toggle'),
  sidebar: document.getElementById('sidebar'),
  sidebarOverlay: document.getElementById('sidebar-overlay')
};

// ========================================
// MOBILE MENU MANAGEMENT
// ========================================
function initMobileMenu() {
  if (elements.mobileMenuToggle && elements.sidebar && elements.sidebarOverlay) {
    // Toggle sidebar
    elements.mobileMenuToggle.addEventListener('click', toggleSidebar);
    
    // Close sidebar when clicking overlay
    elements.sidebarOverlay.addEventListener('click', closeSidebar);
    
    // Close sidebar on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && elements.sidebar.classList.contains('open')) {
        closeSidebar();
      }
    });
    
    // Close sidebar when a chat is selected or action is performed
    elements.chatHistory?.addEventListener('click', (e) => {
      if (e.target.closest('.chat-list-item')) {
        closeSidebar();
      }
    });
    
    elements.newChatBtn?.addEventListener('click', () => {
      setTimeout(closeSidebar, 100);
    });
  }
}

function toggleSidebar() {
  elements.sidebar.classList.toggle('open');
  elements.sidebarOverlay.classList.toggle('active');
  document.body.style.overflow = elements.sidebar.classList.contains('open') ? 'hidden' : '';
}

function closeSidebar() {
  elements.sidebar.classList.remove('open');
  elements.sidebarOverlay.classList.remove('active');
  document.body.style.overflow = '';
}

// ========================================
// THEME MANAGEMENT
// ========================================
function initTheme() {
  const savedTheme = localStorage.getItem('theme') || 'light';
  document.documentElement.setAttribute('data-theme', savedTheme);
}

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute('data-theme');
  const newTheme = currentTheme === 'light' ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', newTheme);
  localStorage.setItem('theme', newTheme);
  BehaviorTracker.log('theme_change', 'interaction', { theme: newTheme });
}

// ========================================
// CHAT HISTORY
// ========================================
async function loadChatHistory() {
  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'list', userId: getUserId() })
    });
    const data = await res.json();
    renderChatHistory(data.chats || []);
  } catch (error) {
    console.error('Chat history load error:', error);
    elements.chatHistory.innerHTML = '<div class="chat-list-empty">' + t('chat.loadFailed') + '</div>';
  }
}

function renderChatHistory(chats) {
  if (!chats.length) {
    elements.chatHistory.innerHTML = '<div class="chat-list-empty">' + t('nav.noChats') + '</div>';
    return;
  }
  
  elements.chatHistory.innerHTML = chats.map(chat => {
    // Başlık yoksa veya eski Türkçe default ise çevirilmiş versiyonu göster
    const title = (!chat.title || chat.title === 'Yeni Sohbet') ? t('nav.newChat') : chat.title;
    return `<div class="chat-list-item ${chat._id === currentChatId ? 'active' : ''}" 
         data-id="${chat._id}">
      ${title}
    </div>`;
  }).join('');
  
  // Add click handlers
  elements.chatHistory.querySelectorAll('.chat-list-item').forEach(item => {
    item.addEventListener('click', () => loadChat(item.dataset.id));
  });
}

// ========================================
// CHAT OPERATIONS
// ========================================
async function loadChat(chatId) {
  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'get', chatId, userId: getUserId() })
    });
    const data = await res.json();
    currentChatId = chatId;
    messages = data.messages || [];
    renderMessages();
    loadChatHistory();
    showChatView();
  } catch (error) {
    console.error('Chat load error:', error);
  }
}

async function startNewChat() {
  // Mevcut sohbet boşsa yeni sohbet açma
  if (currentChatId && messages.length === 0) {
    console.log('Mevcut sohbet zaten boş, direkt chat view göster');
    showChatView();
    return;
  }
  
  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'new', userId: getUserId() })
    });
    const data = await res.json();
    currentChatId = data.chatId;
    messages = [];
    renderMessages();
    loadChatHistory();
    showChatView();
    trackEvent('chat_start');
  } catch (error) {
    console.error('New chat error:', error);
  }
}

async function sendMessage(content = null) {
  const text = content || elements.chatInput.value.trim();
  if (!text) return;
  
  // Disabled durumunda işlem yapma
  if (elements.sendBtn.disabled) return;
  
  trackEvent('message_sent', { mode: currentMode });
  BehaviorTracker.log('message_sent', 'feature', { mode: currentMode, length: (content || elements.chatInput.value.trim()).length });
  const msgSentTime = Date.now();
  
  // chatId yoksa önce yeni sohbet oluştur
  if (!currentChatId) {
    try {
      const newChatRes = await fetch(API_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ action: 'new', userId: getUserId() })
      });
      const newChatData = await newChatRes.json();
      currentChatId = newChatData.chatId;
    } catch (error) {
      console.error('New chat error:', error);
      return;
    }
  }
  
  // Clear input
  elements.chatInput.value = '';
  autoResizeTextarea();
  
  // Add user message to UI immediately
  messages.push({ role: 'user', content: text });
  renderMessages();
  showChatView();
  
  // Disable send button
  elements.sendBtn.disabled = true;
  elements.sendBtn.style.opacity = '0.5';
  
  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ 
        action: 'message', 
        chatId: currentChatId, 
        content: text,
        userId: getUserId(),
        mode: currentMode,
        language: I18n.currentLang
      })
    });
    const data = await res.json();
    
    if (data.messages) {
      messages = data.messages;
      renderMessages();
      BehaviorTracker.log('ai_response', 'feature', { mode: currentMode, responseTime: Date.now() - msgSentTime });
    }
    
    // Update chat ID if new
    if (data.chatId && !currentChatId) {
      currentChatId = data.chatId;
    }
    
    loadChatHistory();
  } catch (error) {
    console.error('Send message error:', error);
    BehaviorTracker.trackError('message_send_failed', { error: error.message });
    // Add error message
    messages.push({ 
      role: 'assistant', 
      content: t('chat.errorMessage') 
    });
    renderMessages();
  } finally {
    // Re-enable send button
    elements.sendBtn.disabled = false;
    elements.sendBtn.style.opacity = '1';
    elements.sendBtn.style.transform = ''; // Reset transform
    
    // Focus input (sadece desktop'ta)
    if (window.innerWidth > 768) {
      elements.chatInput.focus();
    }
  }
}

async function clearAllChats() {
  if (!confirm(t('chat.confirmClear'))) return;
  
  try {
    await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ action: 'deleteAll', userId: getUserId() })
    });
    currentChatId = null;
    messages = [];
    renderMessages();
    loadChatHistory();
    showWelcomeView();
  } catch (error) {
    console.error('Clear chats error:', error);
  }
}

// ========================================
// UI RENDERING
// ========================================
function renderMessages() {
  if (!messages.length) {
    elements.chatMessages.innerHTML = '';
    return;
  }
  
  elements.chatMessages.innerHTML = messages.map(msg => `
    <div class="message ${msg.role === 'user' ? 'user' : 'ai'}">
      <div class="message-avatar">
        ${msg.role === 'user' ? '👤' : '✨'}
      </div>
      <div class="message-content">${formatMessage(msg.content)}</div>
    </div>
  `).join('');
  
  // Scroll to bottom
  elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
}

function formatMessage(content) {
  // HTML entity escape (XSS koruması)
  const escaped = content
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
  // Basic markdown-like formatting
  return escaped
    .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
    .replace(/\*(.*?)\*/g, '<em>$1</em>')
    .replace(/\n/g, '<br>');
}

function showWelcomeView() {
  elements.welcomeScreen.classList.remove('hidden');
  elements.chatMessages.classList.remove('active');
}

function showChatView() {
  elements.welcomeScreen.classList.add('hidden');
  elements.chatMessages.classList.add('active');
  BehaviorTracker.trackPageView('chat');
  
  // Focus input
  if (elements.chatInput) {
    elements.chatInput.focus();
  }
}

// ========================================
// WEATHER MODAL
// ========================================
function openWeatherModal() {
  trackEvent('weather_check');
  BehaviorTracker.trackPageView('weather');
  BehaviorTracker.trackFeatureUsage('weather_check');
  elements.weatherModalOverlay.classList.add('active');
  loadWeather();
}

function closeWeatherModal() {
  elements.weatherModalOverlay.classList.remove('active');
}

async function loadWeather() {
  elements.weatherStats.innerHTML = '';
  elements.weatherAnalysisContent.innerHTML = t('weather.loading');
  elements.weatherLocation.textContent = t('weather.locating');
  elements.weatherDate.textContent = '';
  
  try {
    const res = await fetch(WEATHER_URL);
    const data = await res.json();
    
    if (data && data.weather) {
      elements.weatherLocation.textContent = data.weather.location || t('weather.locationNotFound');
      const dateLocale = I18n.currentLang === 'zh' ? 'zh-CN' : I18n.currentLang === 'en' ? 'en-US' : 'tr-TR';
      elements.weatherDate.textContent = data.weather.date || new Date().toLocaleDateString(dateLocale);
      elements.weatherHeaderIcon.textContent = data.weather.icon || '🌤️';
      
      elements.weatherStats.innerHTML = `
        <div class="weather-stat">
          <div class="weather-stat-icon">🌡️</div>
          <div class="weather-stat-value">${data.weather.temp || '--'}°C</div>
          <div class="weather-stat-label">${t('weather.temp')}</div>
        </div>
        <div class="weather-stat">
          <div class="weather-stat-icon">💧</div>
          <div class="weather-stat-value">${data.weather.humidity || '--'}%</div>
          <div class="weather-stat-label">${t('weather.humidity')}</div>
        </div>
        <div class="weather-stat">
          <div class="weather-stat-icon">🌬️</div>
          <div class="weather-stat-value">${data.weather.wind || '--'} km/h</div>
          <div class="weather-stat-label">${t('weather.wind')}</div>
        </div>
        <div class="weather-stat">
          <div class="weather-stat-icon">☀️</div>
          <div class="weather-stat-value">${data.weather.uv || '--'}</div>
          <div class="weather-stat-label">${t('weather.uvIndex')}</div>
        </div>
      `;
      
      elements.weatherAnalysisContent.textContent = data.analysis || t('weather.analysisNotFound');
    } else {
      elements.weatherAnalysisContent.textContent = t('weather.dataError');
    }
  } catch (error) {
    console.error('Weather load error:', error);
    elements.weatherAnalysisContent.textContent = t('weather.loadError');
  }
}

// ========================================
// INPUT HANDLING - MOBİL İYİLEŞTİRMELERİ
// ========================================
function autoResizeTextarea() {
  const textarea = elements.chatInput;
  if (!textarea) return;
  
  // Reset height first to get accurate scrollHeight
  textarea.style.height = 'auto';
  
  // Calculate new height with proper padding (mobil için azaltılmış)
  const scrollHeight = textarea.scrollHeight;
  const newHeight = Math.min(scrollHeight, 150);
  
  textarea.style.height = newHeight + 'px';
  textarea.style.overflowY = scrollHeight > 150 ? 'auto' : 'hidden';
}

function handleKeyDown(e) {
  // Enter ile gönderme (Shift+Enter ile yeni satır)
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
  }
}

// Mobil için geliştirilmiş gönder butonu işleyicisi
function handleSendButton(e) {
  e.preventDefault(); // Varsayılan davranışı engelle
  e.stopPropagation(); // Event bubbling'i durdur
  
  // Disabled kontrolü
  if (elements.sendBtn.disabled) return;
  
  // Mesaj gönder
  sendMessage();
}

// ========================================
// MOBİL KLAVYE UYUMLULUK
// ========================================
function adjustForKeyboard() {
  // Mobil klavye açıldığında viewport yüksekliği değişir
  const viewportHeight = window.innerHeight;
  const isKeyboardOpen = viewportHeight < window.screen.height * 0.75;
  
  if (isKeyboardOpen && elements.chatMessages) {
    // Klavye açıkken mesajları scroll et
    setTimeout(() => {
      elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
    }, 100);
  }
}

// ========================================
// MODE SELECTION
// ========================================
function selectMode(btn) {
  elements.modeBtns.forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  currentMode = btn.dataset.mode || 'care';
  trackEvent('mode_change', { mode: currentMode });
}

// ========================================
// EVENT LISTENERS - MOBİL GÜNCELLEMELER
// ========================================
function initEventListeners() {
  // Theme toggle
  elements.themeToggle?.addEventListener('click', toggleTheme);
  
  // Chat operations
  elements.newChatBtn?.addEventListener('click', startNewChat);
  elements.clearHistoryBtn?.addEventListener('click', clearAllChats);
  
  // SEND BUTTON - Mobil uyumlu event handlers
  if (elements.sendBtn) {
    let isTouching = false;
    
    // Touch events (mobile) - touch olduğunda click'i engelle
    elements.sendBtn.addEventListener('touchstart', (e) => {
      e.preventDefault();
      isTouching = true;
      elements.sendBtn.style.transform = 'scale(0.95)';
    }, { passive: false });
    
    elements.sendBtn.addEventListener('touchend', (e) => {
      e.preventDefault();
      elements.sendBtn.style.transform = '';
      handleSendButton(e);
      setTimeout(() => { isTouching = false; }, 300);
    });
    
    elements.sendBtn.addEventListener('touchcancel', () => {
      elements.sendBtn.style.transform = '';
      isTouching = false;
    });
    
    // Mouse click (desktop) - touch sonrası click'i engelle
    elements.sendBtn.addEventListener('click', (e) => {
      if (isTouching) return;
      handleSendButton(e);
    });
  }
  
  // Input handling
  if (elements.chatInput) {
    elements.chatInput.addEventListener('input', autoResizeTextarea);
    elements.chatInput.addEventListener('keydown', handleKeyDown);
    
    // Mobil klavye açıldığında scroll problemi çözümü
    elements.chatInput.addEventListener('focus', () => {
      setTimeout(() => {
        if (elements.chatMessages.scrollHeight > 0) {
          elements.chatMessages.scrollTop = elements.chatMessages.scrollHeight;
        }
      }, 300); // Klavye açılma animasyonu için gecikme
    });
  }
  
  // Weather modal
  elements.weatherCard?.addEventListener('click', openWeatherModal);
  elements.weatherModalClose?.addEventListener('click', closeWeatherModal);
  elements.weatherRefresh?.addEventListener('click', loadWeather);
  elements.weatherModalOverlay?.addEventListener('click', (e) => {
    if (e.target === elements.weatherModalOverlay) closeWeatherModal();
  });
  
  // Mode buttons
  elements.modeBtns.forEach(btn => {
    btn.addEventListener('click', () => selectMode(btn));
  });
  
  // Quick action buttons
  elements.quickActionBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const prompt = btn.dataset.prompt;
      if (prompt) sendMessage(prompt);
    });
  });
  
  // Viewport resize handler (mobil klavye için)
  // Otomatik resize devre dışı bırakıldı - CSS interactive-widget ile çözülecek
  /*
  let resizeTimer;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => {
      adjustForKeyboard();
    }, 100);
  });
  */
}
// ========================================
// LANGUAGE SELECTOR
// ========================================
function initLangSelector() {
  const switcher = document.getElementById('lang-switcher');
  if (!switcher) return;
  
  const flags = switcher.querySelectorAll('.lang-flag');
  
  // Dil seçimi - bayrak butonları
  flags.forEach(flag => {
    flag.addEventListener('click', async () => {
      const lang = flag.dataset.lang;
      // Active state güncelle
      flags.forEach(f => f.classList.remove('active'));
      flag.classList.add('active');
      // Dili değiştir
      await I18n.setLanguage(lang);
      BehaviorTracker.log('language_change', 'interaction', { language: lang });
      trackEvent('language_change', { language: lang });
    });
  });

  // Sayfa yüklendiğinde aktif dili işaretle
  const currentLang = I18n.currentLang || 'tr';
  flags.forEach(f => {
    f.classList.toggle('active', f.dataset.lang === currentLang);
  });

  // Dil değiştiğinde dinamik içerikleri güncelle
  window.addEventListener('languageChanged', () => {
    // Bayrak active state güncelle
    const lang = I18n.currentLang;
    flags.forEach(f => f.classList.toggle('active', f.dataset.lang === lang));
    // Sohbet geçmişini yeniden render et
    if (currentUser) loadChatHistory();
    // Bildirim butonunu güncelle
    document.querySelectorAll('.notification-toggle-btn').forEach(btn => {
      const enabled = Notification.permission === 'granted';
      btn.textContent = enabled ? t('notification.on') : t('notification.off');
    });
  });
}

// ========================================
// INITIALIZATION
// ========================================
async function init() {
  console.log('🚀 Women AI başlatılıyor...');
  
  // i18n başlat (önce dil yüklensin)
  await I18n.init();
  
  // Davranış takip sistemini başlat
  BehaviorTracker.init();
  
  initTheme();
  initMobileMenu();
  initLangSelector();
  initEventListeners();
  initReminderSettings(); // Hatırlatıcı ayarları
  initProfilePage(); // Profil sayfası
  const authLoadedChats = await initGoogleAuth(); // Google OAuth başlat
  
  // Sadece giriş yapılmışsa VE initGoogleAuth içinde yüklenmediyse sohbetleri yükle
  if (currentUser && !authLoadedChats) {
    try {
      await loadChatHistory();
      await startNewChat();
    } catch (error) {
      console.error('Chat history load error:', error);
    }
    
    // Input'ları aktif tut
    setTimeout(() => {
      if (elements.chatInput) {
        elements.chatInput.disabled = false;
        elements.chatInput.readOnly = false;
      }
      if (elements.sendBtn) {
        elements.sendBtn.disabled = false;
      }
    }, 500);
  }
  
  console.log('✅ Women AI hazır!');
}

document.addEventListener('DOMContentLoaded', init);

// ========================================
// PWA SERVICE WORKER REGISTRATION
// ========================================
if ('serviceWorker' in navigator) {
  window.addEventListener('load', async () => {
    try {
      const reg = await navigator.serviceWorker.register('/sw.js', { scope: '/' });
      console.log('✅ SW registered:', reg.scope);

      // Yeni SW varsa güncelle
      reg.addEventListener('updatefound', () => {
        const newSW = reg.installing;
        if (newSW) {
          newSW.addEventListener('statechange', () => {
            if (newSW.state === 'activated') {
              console.log('🔄 Yeni versiyon aktif!');
            }
          });
        }
      });
    } catch (err) {
      console.warn('⚠️ SW registration failed:', err);
    }
  });
}


