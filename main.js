/**
 * Women AI Chat - Main JavaScript
 * Professional ChatGPT-style interface
 * Domain: womenai.semihcankadioglu.com.tr
 */

// Configuration
const API_URL = '/api/chat';
const WEATHER_URL = '/api/weather';
const GOOGLE_CLIENT_ID = ''; // .env'den alınacak, başlangıçta boş

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
    alert('Google Sign-In yüklenemedi. Sayfayı yenileyin.');
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
      console.log('✅ Google ile giriş başarılı:', data.user.name);
    } else {
      console.error('Google giriş hatası:', data.error);
      alert('Giriş başarısız: ' + (data.error || 'Bilinmeyen hata'));
    }
  } catch (err) {
    console.error('Google auth error:', err);
    alert('Giriş sırasında bir hata oluştu');
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

  if (currentUser) {
    // Giriş yapılmış - chat alanını göster
    if (loginScreen) loginScreen.style.display = 'none';
    if (chatContainer) chatContainer.style.display = 'flex';
    if (sidebar) sidebar.classList.remove('login-required');
    if (mobileMenuToggle) {
      mobileMenuToggle.classList.remove('hidden');
    }
    if (mainContent) mainContent.classList.remove('login-active');
    if (inputContainer) inputContainer.style.display = 'block';
  } else {
    // Giriş yapılmamış - login ekranını göster
    if (loginScreen) loginScreen.style.display = 'flex';
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
    if (userName) userName.textContent = currentUser.name || 'Kullanıcı';
    if (userEmail) userEmail.textContent = currentUser.email || '';
  } else {
    // Misafir kullanıcı
    if (userGuest) userGuest.style.display = 'block';
    if (userProfile) userProfile.style.display = 'none';
  }
}

function initGoogleAuth() {
  // URL'den auth bilgisini kontrol et (OAuth callback'ten redirect)
  const urlParams = new URLSearchParams(window.location.search);
  const authData = urlParams.get('auth_success');
  
  if (authData) {
    try {
      // URL-safe base64'ü normal base64'e çevir
      const base64 = authData.replace(/-/g, '+').replace(/_/g, '/');
      const padding = base64.length % 4;
      const paddedBase64 = padding ? base64 + '='.repeat(4 - padding) : base64;
      
      const userData = JSON.parse(atob(paddedBase64));
      currentUser = userData;
      localStorage.setItem('womenai_user', JSON.stringify(userData));
      
      // URL'den auth parametresini temizle
      window.history.replaceState({}, document.title, window.location.pathname);
      
      console.log('✅ OAuth ile giriş başarılı:', userData.name);
      updateUserUI();
      updateLoginState();
      return; // Zaten giriş yapıldı, devam etme
    } catch (e) {
      console.error('Auth data parse error:', e);
    }
  }
  
  // Local storage'dan kullanıcıyı yükle
  const savedUser = localStorage.getItem('womenai_user');
  if (savedUser) {
    try {
      currentUser = JSON.parse(savedUser);
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
  const btn = document.getElementById('notification-toggle');
  if (btn) {
    btn.textContent = enabled ? '🔔 Bildirimler Açık' : '🔕 Bildirimleri Aç';
    btn.classList.toggle('active', enabled);
  }
}

function showInAppNotification(title, body) {
  // Uygulama içi bildirim toast
  const toast = document.createElement('div');
  toast.className = 'notification-toast';
  toast.innerHTML = `
    <div class="notification-toast-icon">💜</div>
    <div class="notification-toast-content">
      <div class="notification-toast-title">${title || 'Women AI'}</div>
      <div class="notification-toast-body">${body || ''}</div>
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
    elements.chatHistory.innerHTML = '<div class="chat-list-empty">Yüklenemedi</div>';
  }
}

function renderChatHistory(chats) {
  if (!chats.length) {
    elements.chatHistory.innerHTML = '<div class="chat-list-empty">Henüz sohbet yok</div>';
    return;
  }
  
  elements.chatHistory.innerHTML = chats.map(chat => `
    <div class="chat-list-item ${chat._id === currentChatId ? 'active' : ''}" 
         data-id="${chat._id}">
      ${chat.title || 'Yeni Sohbet'}
    </div>
  `).join('');
  
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
  } catch (error) {
    console.error('New chat error:', error);
  }
}

async function sendMessage(content = null) {
  const text = content || elements.chatInput.value.trim();
  if (!text) return;
  
  // Disabled durumunda işlem yapma
  if (elements.sendBtn.disabled) return;
  
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
        mode: currentMode
      })
    });
    const data = await res.json();
    
    if (data.messages) {
      messages = data.messages;
      renderMessages();
    }
    
    // Update chat ID if new
    if (data.chatId && !currentChatId) {
      currentChatId = data.chatId;
    }
    
    loadChatHistory();
  } catch (error) {
    console.error('Send message error:', error);
    // Add error message
    messages.push({ 
      role: 'assistant', 
      content: 'Üzgünüm, bir hata oluştu. Lütfen tekrar deneyin.' 
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
  if (!confirm('Tüm sohbet geçmişi silinecek. Emin misiniz?')) return;
  
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
  // Basic markdown-like formatting
  return content
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
  
  // Focus input
  if (elements.chatInput) {
    elements.chatInput.focus();
  }
}

// ========================================
// WEATHER MODAL
// ========================================
function openWeatherModal() {
  elements.weatherModalOverlay.classList.add('active');
  loadWeather();
}

function closeWeatherModal() {
  elements.weatherModalOverlay.classList.remove('active');
}

async function loadWeather() {
  elements.weatherStats.innerHTML = '';
  elements.weatherAnalysisContent.innerHTML = 'Yükleniyor...';
  elements.weatherLocation.textContent = 'Konum alınıyor...';
  elements.weatherDate.textContent = '';
  
  try {
    const res = await fetch(WEATHER_URL);
    const data = await res.json();
    
    if (data && data.weather) {
      elements.weatherLocation.textContent = data.weather.location || 'Konum bulunamadı';
      elements.weatherDate.textContent = data.weather.date || new Date().toLocaleDateString('tr-TR');
      elements.weatherHeaderIcon.textContent = data.weather.icon || '🌤️';
      
      elements.weatherStats.innerHTML = `
        <div class="weather-stat">
          <div class="weather-stat-icon">🌡️</div>
          <div class="weather-stat-value">${data.weather.temp || '--'}°C</div>
          <div class="weather-stat-label">Sıcaklık</div>
        </div>
        <div class="weather-stat">
          <div class="weather-stat-icon">💧</div>
          <div class="weather-stat-value">${data.weather.humidity || '--'}%</div>
          <div class="weather-stat-label">Nem</div>
        </div>
        <div class="weather-stat">
          <div class="weather-stat-icon">🌬️</div>
          <div class="weather-stat-value">${data.weather.wind || '--'} km/s</div>
          <div class="weather-stat-label">Rüzgar</div>
        </div>
        <div class="weather-stat">
          <div class="weather-stat-icon">☀️</div>
          <div class="weather-stat-value">${data.weather.uv || '--'}</div>
          <div class="weather-stat-label">UV İndeksi</div>
        </div>
      `;
      
      elements.weatherAnalysisContent.innerHTML = data.analysis || 'Analiz bulunamadı.';
    } else {
      elements.weatherAnalysisContent.innerHTML = 'Hava durumu bilgisi alınamadı.';
    }
  } catch (error) {
    console.error('Weather load error:', error);
    elements.weatherAnalysisContent.innerHTML = 'Hava durumu yüklenirken hata oluştu.';
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
    // Mouse click (desktop)
    elements.sendBtn.addEventListener('click', handleSendButton);
    
    // Touch events (mobile)
    elements.sendBtn.addEventListener('touchstart', (e) => {
      e.preventDefault(); // Çift tıklama engellemesi
      elements.sendBtn.style.transform = 'scale(0.95)'; // Görsel feedback
    });
    
    elements.sendBtn.addEventListener('touchend', handleSendButton);
    
    elements.sendBtn.addEventListener('touchcancel', () => {
      elements.sendBtn.style.transform = ''; // Reset
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
// INITIALIZATION
// ========================================
async function init() {
  console.log('🚀 Women AI başlatılıyor...');
  
  initTheme();
  initMobileMenu();
  initEventListeners();
  initGoogleAuth(); // Google OAuth başlat (bu updateLoginState'i de çağırır)
  
  // Sadece giriş yapılmışsa sohbetleri yükle
  if (currentUser) {
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


