/**
 * Women AI Chat - Main JavaScript
 * Professional ChatGPT-style interface
 * Domain: womenai.semihcankadioglu.com.tr
 */

// Configuration
const API_URL = '/api/chat';
const WEATHER_URL = '/api/weather';

// State
let currentChatId = null;
let messages = [];
let currentMode = 'care';

// ========================================
// USER ID MANAGEMENT (Visitor Tracking)
// ========================================
function getUserId() {
  let visitorId = localStorage.getItem('womenai_visitor_id');
  if (!visitorId) {
    // Generate unique visitor ID
    visitorId = 'visitor_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
    localStorage.setItem('womenai_visitor_id', visitorId);
  }
  return visitorId;
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
  quickActionBtns: document.querySelectorAll('.quick-action-btn')
};

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
    console.log('Mevcut sohbet zaten boş, yeni sohbet açılmadı');
    showWelcomeView();
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
    showWelcomeView();
  } catch (error) {
    console.error('New chat error:', error);
  }
}

async function sendMessage(content = null) {
  const text = content || elements.chatInput.value.trim();
  if (!text) return;
  
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
    elements.sendBtn.disabled = false;
    elements.chatInput.focus();
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
// INPUT HANDLING
// ========================================
function autoResizeTextarea() {
  const textarea = elements.chatInput;
  textarea.style.height = 'auto';
  textarea.style.height = Math.min(textarea.scrollHeight, 200) + 'px';
}

function handleKeyDown(e) {
  if (e.key === 'Enter' && !e.shiftKey) {
    e.preventDefault();
    sendMessage();
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
// EVENT LISTENERS
// ========================================
function initEventListeners() {
  // Theme toggle
  elements.themeToggle.addEventListener('click', toggleTheme);
  
  // Chat operations
  elements.newChatBtn.addEventListener('click', startNewChat);
  elements.clearHistoryBtn.addEventListener('click', clearAllChats);
  elements.sendBtn.addEventListener('click', () => sendMessage());
  
  // Input handling
  elements.chatInput.addEventListener('input', autoResizeTextarea);
  elements.chatInput.addEventListener('keydown', handleKeyDown);
  
  // Weather modal
  elements.weatherCard.addEventListener('click', openWeatherModal);
  elements.weatherModalClose.addEventListener('click', closeWeatherModal);
  elements.weatherRefresh.addEventListener('click', loadWeather);
  elements.weatherModalOverlay.addEventListener('click', (e) => {
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
}

// ========================================
// INITIALIZATION
// ========================================
async function init() {
  initTheme();
  initEventListeners();
  await loadChatHistory();
  
  // Hiç sohbet yoksa yeni oluştur
  if (!currentChatId) {
    await startNewChat();
  }
}

// Start app
document.addEventListener('DOMContentLoaded', init);
