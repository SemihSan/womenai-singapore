# Women AI - Proje Rehberi (AI Oturum Notu)

> **Son Güncelleme:** 10 Şubat 2026 - v2.9
> **Bu dosya AI asistan oturumları arası bağlam aktarımı için hazırlanmıştır.**

---

## 1. PROJE GENEL BAKIŞ

**Proje Adı:** Women AI - Kadınlar İçin Yapay Zeka Asistanı  
**Geliştirici:** Semih Can Kadıoğlu (Mert Group)  
**Domain:** `https://singapur.semihcankadioglu.com.tr`  
**GitHub:** `SemihSan/womenai-singapore` (branch: `main`)  
**Hedef:** Cilt bakımı, beslenme ve motivasyon konularında kadınlara özel AI chatbot. İleride **mobil uygulamaya** dönüştürülecek.

### Teknoloji Stack
| Katman | Teknoloji |
|--------|-----------|
| Backend | Node.js + Express.js |
| Veritabanı | MongoDB (self-hosted, Docker) |
| AI | OpenAI GPT-4o-mini API |
| Auth | Google OAuth 2.0 (Authorization Code Flow) |
| Push | Firebase Admin SDK + FCM |
| Scheduler | node-cron (lazy-loaded, optional) |
| Hosting | Coolify (self-hosted PaaS) |
| Güvenlik | Helmet.js, bcrypt, rate-limiting, CORS |

---

## 2. DOSYA YAPISI VE ROLLERİ

```
├── server.js          # Ana backend (~2460 satır). Tüm API'ler, schema'lar, scheduler
├── index.html         # Tek sayfa uygulama (~588 satır). Tüm UI modalları dahil
├── main.js            # Frontend JS (~1660 satır). Auth, chat, profil, anket, push
├── style.css          # Tüm CSS stilleri (tema, responsive, modallar)
├── admin-panel.html   # Admin paneli arayüzü (ayrı sayfa, /admin yolunda)
├── package.json       # Dependencies: express, mongoose, firebase-admin, node-cron...
├── README.md          # Proje açıklaması
├── SISTEM-DOKUMANTASYONU.md  # Eski dokümantasyon
└── PROJE-REHBER.md    # BU DOSYA - AI oturum bağlamı
```

---

## 3. DEPLOYMENT (Coolify)

### Ortam Bilgileri
- **Sunucu SSH:** `root@129.212.226.101`
- **Docker Container:** Coolify otomatik yönetir (Nixpacks builder)
- **Auto-deploy:** `main` branch'e push = otomatik deploy

### Environment Variables (Coolify'da tanımlı)
```
NIXPACKS_NODE_VERSION=22
PORT=3000
NODE_ENV=production
MONGODB_URI=mongodb://root:...@lskw0c48wk88cwskcowkogwc:27017/?directConnection=true
OPENAI_API_KEY=sk-...
GOOGLE_CLIENT_ID=<REDACTED - Coolify'den al>
GOOGLE_CLIENT_SECRET=<REDACTED - Coolify'den al>
FIREBASE_SERVICE_ACCOUNT={...büyük JSON...}
FIREBASE_API_KEY=...
FIREBASE_AUTH_DOMAIN=...
FIREBASE_PROJECT_ID=singapur-96d17
FIREBASE_STORAGE_BUCKET=...
FIREBASE_MESSAGING_SENDER_ID=...
FIREBASE_APP_ID=...
FIREBASE_VAPID_KEY=...
```

### Deploy Süreci
```bash
git add -A
git commit -m "açıklama"
git push origin main
# Coolify webhook ile otomatik build+deploy başlar
```

### Bilinen Sorun: 502 Bad Gateway
Bir seferinde `curl localhost:3000` container içinden bile connection refused verdi. `app.listen(PORT, '0.0.0.0', ...)` ile düzeltildi. Tekrar olursa:
1. SSH: `ssh root@129.212.226.101`
2. Container ID bul: `docker ps | grep singapur`
3. Loglar: `docker logs <container_id> --tail 50`
4. Container içi test: `docker exec -it <container_id> sh` → `curl localhost:3000/health`

---

## 4. VERİTABANI ŞEMALARI (MongoDB)

### 4.1 Chat Schema
```javascript
{
  userId: String,         // "google_<mongoId>" formatında
  title: String,          // İlk mesajdan auto-generate
  mode: String,           // 'care' | 'motivation' | 'diet'
  isArchived: Boolean,
  isFavorite: Boolean,
  messages: [{
    role: 'user' | 'assistant',
    content: String,
    timestamp: Date
  }],
  createdAt: Date,
  updatedAt: Date
}
```

### 4.2 User Schema (Google OAuth)
```javascript
{
  googleId: String,       // Google'dan gelen unique ID
  email: String,
  name: String,
  picture: String,        // Google profil fotoğrafı URL
  visitorId: String,      // Eski anonim ID (migration için)
  profile: {              // ← ANKET SİSTEMİ (v2.9'da eklendi)
    skinType: String,     // 'kuru'|'yagli'|'karma'|'normal'|'hassas'
    skinConcerns: [String],  // ['akne','leke','kirisiklik','gozenek','kuruluk','kizariklik','matlik','sarkma']
    age: String,          // '18-24'|'25-34'|'35-44'|'45-54'|'55+'
    gender: String,       // 'kadin'|'erkek'|'belirtmek-istemiyorum'
    region: String,       // Şehir adı
    allergies: [String],  // ['parfüm','retinol','aha-bha','vitamin-c','niacinamide','alkol','paraben']
    sensitivities: [String], // ['güneş','soğuk','sıcak','stres','hormon','kirlilik']
    isProfileComplete: Boolean,
    completedAt: Date
  },
  createdAt: Date,
  lastLogin: Date
}
```

### 4.3 AdminSettings Schema
```javascript
{
  systemPrompt: String,   // Ana sistem prompt (çok uzun, ürün kataloğu dahil)
  carePrompt: String,     // Bakım modu ek prompt
  motivationPrompt: String,
  dietPrompt: String,
  temperature: Number,    // default 0.6
  model: String,          // default 'gpt-4o-mini'
  maxMessageLength: Number,
  blacklist: [String],    // Yasaklı kelimeler
  maxTokens: Number,
  frequencyPenalty: Number,
  presencePenalty: Number,
  topP: Number
}
```

### 4.4 AdminUser Schema
```javascript
{
  username: String,       // 'admin'
  password: String,       // bcrypt hash (clear: 'WomenAI2026!')
  shopDomain: String,
  sessionToken: String,
  tokenExpiry: Date
}
```

### 4.5 PushSubscription Schema
```javascript
{
  userId: String,
  fcmToken: String,
  device: String,
  preferences: {
    skincare: Boolean,    // Cilt bakımı hatırlatıcıları
    water: Boolean,       // Su içme hatırlatıcıları
    motivation: Boolean,
    news: Boolean
  },
  reminderTimes: {
    morning: String,      // '08:00' formatında
    evening: String,      // '21:00' formatında
    waterInterval: Number // Saat cinsinden (1-4)
  },
  timezone: String,
  isActive: Boolean,
  lastNotification: Date
}
```

---

## 5. API ENDPOINTLERİ

### Frontend API (Unified)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/chat` | Tüm chat işlemleri (action-based) |
| | action: `list` | Kullanıcının sohbet listesi |
| | action: `get` | Tek sohbet detay |
| | action: `new` | Yeni sohbet oluştur |
| | action: `message` | Mesaj gönder (AI yanıt alır) |
| | action: `deleteAll` | Tüm sohbetleri sil |

### Auth API
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/auth/google/callback` | OAuth redirect handler |
| POST | `/api/auth/google` | One Tap token doğrulama |
| POST | `/api/auth/google/code` | Authorization code → token |
| POST | `/api/auth/migrate-chats` | Visitor → Google hesap geçişi |
| GET | `/api/auth/user/:userId` | Kullanıcı bilgileri + profil |

### Profil Anketi API (v2.9)
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| PUT | `/api/user/profile` | Profil anketini kaydet/güncelle |
| GET | `/api/user/profile/:userId` | Profil bilgilerini getir |

### Push Notification API
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/api/push/subscribe` | FCM token kaydet |
| POST | `/api/push/unsubscribe` | Bildirim kapat |
| PUT | `/api/push/preferences` | Hatırlatıcı tercihlerini güncelle |
| GET | `/api/push/preferences` | Tercihleri getir (fcmToken ile) |
| POST | `/api/push/test` | Admin test bildirimi |
| POST | `/api/push/test-self` | Kullanıcı kendi test bildirimi |
| POST | `/api/push/broadcast` | Toplu bildirim (Admin) |
| GET | `/api/push/stats` | Abone istatistikleri (Admin) |

### Admin API
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| POST | `/admin/login` | Admin giriş (username+password) |
| POST | `/admin/logout` | Admin çıkış |
| GET | `/admin/settings` | AI ayarlarını getir |
| PUT | `/admin/settings` | AI ayarlarını güncelle |
| GET | `/admin/stats` | Genel istatistikler |
| GET | `/admin` | Admin panel HTML |

### Diğer
| Method | Endpoint | Açıklama |
|--------|----------|----------|
| GET | `/api/config` | Frontend config (Google Client ID, Firebase) |
| GET | `/health` | Health check |
| GET | `/api/weather` | Hava durumu + cilt analizi |

---

## 6. ÖZELLİK DETAYLARI

### 6.1 Google OAuth Akışı
1. Kullanıcı "Google ile Giriş Yap" butonuna tıklar
2. **Desktop:** Popup penceresi açılır → Google hesap seçimi
3. **Mobil:** Aynı pencerede redirect olur (popup'lar sorunlu)
4. Google, `/auth/google/callback?code=...` adresine yönlendirir
5. Server: code → token → userInfo → User upsert → base64 userData
6. Redirect: `/?auth_success=<base64>` → Frontend parse eder → localStorage'a kaydeder
7. `currentUser` global değişkeni set edilir, UI güncellenir

**userId formatı:** Frontend'de `google_<mongoId>` olarak kullanılır (getUserId fonksiyonu).

### 6.2 Chat Sistemi
- **Unified API:** Tek `/api/chat` endpoint'i, `action` parametresiyle yönlendirme
- **Mod sistemi:** Bakım (care), Motivasyon (motivation), Beslenme (diet)
- **Mod prompt:** Her mod için ayrı ek prompt, AdminSettings'den yönetilir
- **Mesaj limiti:** Son 10 mesaj context olarak gönderilir
- **Blacklist:** Yasaklı kelime filtresi (server-side)
- **Ürün RAG:** Mini RAG sistemi (SHADLESS_PRODUCTS array) - 7 ürün, tag-based skor

### 6.3 Profil Anketi Sistemi (v2.9 - EN SON EKLENDİ)

**Nasıl çalışır:**

1. **Tetikleme:** Kullanıcı profil modalında "📝 Profil Anketini Doldur" butonuna tıklar
2. **4 Adımlı Wizard Modal açılır:**
   - **Adım 1:** Cilt tipi seçimi (5 radio: kuru/yağlı/karma/normal/hassas) + Cilt sorunları (8 checkbox chip)
   - **Adım 2:** Yaş aralığı (5 radio) + Cinsiyet (3 radio) + Bölge/Şehir (select, Türk şehirleri + Singapur)
   - **Adım 3:** Alerjiler (7 chip: parfüm, retinol, AHA/BHA, vitamin-c, niacinamide, alkol, paraben) + Hassasiyetler (6 chip: güneş, soğuk, sıcak, stres, hormon, kirlilik)
   - **Adım 4:** Özet gösterimi (tüm seçimlerin listesi)
3. **Kaydetme:** "💾 Kaydet" → `PUT /api/user/profile` → MongoDB User.profile alanına yazılır
4. **İsProfileComplete:** true olarak işaretlenir, buton "✅ Profilini Düzenle"ye dönüşür
5. **Mevcut veri yükleme:** Profil daha önce doldurulmuşsa, anket açıldığında mevcut seçimler pre-fill edilir

**AI Kişiselleştirme (Kritik!):**

Chat mesajı gönderildiğinde (`action: 'message'` handler):
1. `userId`'den `google_` prefix'i çıkarılır → `User.findById()` ile kullanıcı çekilir
2. Profil tamamlanmışsa (`isProfileComplete === true`), `profilePrompt` string oluşturulur:
   ```
   👤 KULLANICI PROFİLİ (önerileri buna göre kişiselleştir):
   Cilt tipi: karma
   Cilt sorunları: akne, leke
   Yaş aralığı: 25-34
   Bölge: İstanbul
   Alerjiler: retinol, paraben - BU İÇERİKLERE DİKKAT ET, ÖNERİLERDE BUNLARDAN KAÇIN!
   Hassasiyetler: güneş, stres
   ```
3. Bu prompt, **system prompt'un sonuna eklenir** → AI bu bilgilere göre kişiselleştirilmiş yanıt verir
4. **Alerji uyarısı** özel vurgulanır: "BU İÇERİKLERE DİKKAT ET, ÖNERİLERDE BUNLARDAN KAÇIN!"

**İlgili Kodlar:**
- `server.js` → User schema profile alanı (~satır 298)
- `server.js` → PUT/GET /api/user/profile endpoint'leri (~satır 1320)
- `server.js` → profilePrompt oluşturma (action: 'message' handler içi, ~satır 920)
- `server.js` → profilePrompt'u apiMessages'a ekleme (~satır 950)
- `index.html` → Survey modal HTML (~satır 450-560)
- `main.js` → Survey JS fonksiyonları (~satır 830-1050): openSurveyModal, closeSurveyModal, showSurveyStep, getSurveyData, buildSurveySummary, saveSurveyData, loadExistingSurveyData, updateSurveyButton, initSurveyModal
- `style.css` → Survey stilleri (`.survey-modal`, `.survey-option`, `.survey-chip`, vb.)

### 6.4 Push Notification Sistemi
- **Firebase Admin SDK** server-side (service account JSON, env var'dan)
- **Firebase JS SDK** client-side (config /api/config'den alınır)
- **Service Worker:** `firebase-messaging-sw.js` (FCM background messages)
- **Bildirim izni:** Özel UI prompt (notification-prompt div)
- **Hatırlatıcılar:**
  - Cilt bakımı: Kullanıcının belirlediği sabah/akşam saatlerinde
  - Su içme: Belirlenen interval'da (1-4 saat), 07:00-22:00 arası
  - node-cron her dakika kontrol eder, eşleşen kullanıcılara gönderir
- **Broadcast:** Admin panelden tüm abonelere toplu bildirim

### 6.5 Profil Sayfası
- Profil avatarı (Google'dan), isim, email
- İstatistikler: Toplam sohbet, toplam mesaj, üyelik süresi (gün)
- En çok kullanılan mod
- Üyelik tarihi, son giriş
- Bildirim durumu
- Profil anketi butonu (tamamlanma durumuna göre değişir)
- Çıkış butonu

### 6.6 Hava Durumu & Cilt Analizi
- Sidebar'da "Hava & Cilt Analizi" kartı → Modal açılır
- `/api/weather` endpoint'i → Sıcaklık, nem, rüzgar, UV indeksi
- AI ile cilt bakım önerisi üretilir

### 6.7 Admin Paneli
- **URL:** `/admin` veya `singapur.semihcankadioglu.com.tr/admin`
- **Giriş:** username: `admin`, password: `WomenAI2026!`
- **Özellikler:**
  - System prompt düzenleme (ana + mod bazlı)
  - AI model parametreleri (temperature, model, maxTokens, vb.)
  - Kullanıcı istatistikleri
  - Push bildirim gönderme (test + broadcast)
  - Blacklist yönetimi

### 6.8 Tema Sistemi
- Light/Dark tema toggle
- `data-theme` attribute ile CSS variables
- localStorage'da saklanır

### 6.9 Mobil Uyumluluk
- Responsive tasarım
- Sidebar hamburger menu (mobile)
- Touch event optimizasyonları (send button)
- Klavye açılma durumu yönetimi
- OAuth mobilde redirect (popup değil)
- `viewport-fit=cover`, `interactive-widget=resizes-content`

---

## 7. FRONTEND MİMARİSİ (main.js)

### Global State
```javascript
let currentChatId = null;    // Aktif sohbet ID
let messages = [];           // Aktif sohbetin mesajları
let currentMode = 'care';   // Seçili mod
let currentUser = null;      // Google ile giriş yapmış kullanıcı objesi
let fcmToken = null;         // Firebase Cloud Messaging token
let pushEnabled = false;     // Push bildirim durumu
let surveyStep = 1;          // Anket adımı (1-4)
```

### Initialization Zinciri (DOMContentLoaded → init)
```
init()
├── initTheme()
├── initMobileMenu()
├── initEventListeners()
├── initReminderSettings()
├── initProfilePage()        // → initSurveyModal() dahil
├── initGoogleAuth()         // → fetchGoogleClientId() → initPushNotifications()
└── loadChatHistory() + startNewChat()  (sadece giriş yapılmışsa)
```

### Önemli Fonksiyonlar
| Fonksiyon | Açıklama |
|-----------|----------|
| `getUserId()` | `google_<id>` veya `visitor_<random>` döner |
| `handleGoogleSignIn(response)` | One Tap callback |
| `openGoogleSignInPopup()` | OAuth popup/redirect |
| `updateLoginState()` | Login/chat ekranları toggle |
| `sendMessage(content)` | API'ye mesaj gönder, UI güncelle |
| `loadChatHistory()` | Sidebar chat listesi yükle |
| `openProfileModal()` | Profil modal aç + stats yükle |
| `openSurveyModal()` | 4 adımlı anket modal aç |
| `saveSurveyData()` | Anket verilerini API'ye kaydet |
| `showInAppNotification(title, body)` | Toast bildirim göster |
| `requestNotificationPermission()` | Push izni iste |

---

## 8. ÜRÜN KATALOĞU (Mini RAG)

AI'ın önerdiği ürünler (SHADLESS_PRODUCTS array'i):

| # | Ürün | URL | Kullanım Alanı |
|---|------|-----|----------------|
| 1 | Cream Cleanser | shadeless.cn/products/cleanser | Kuru/hassas cilt temizleme |
| 2 | Soothing Toner | shadeless.cn/products/soothing-toner | Hassasiyet, kızarıklık |
| 3 | Serum Step-1 | .../serum-step-1 | Gözenek, ton eşitsizliği |
| 4 | Serum Step-2 | .../serum-step-2 | Leke, hiperpigmentasyon |
| 5 | Serum Step-3 | .../serum-step-3 | Anti-aging, kırışıklık |
| 6 | Peptide Mask | .../facial-skincare-mask | Yoğun nem, özel gün |
| 7 | 3-Steps Set | .../3-steps-serums | Komple rutin seti |

**Not:** System prompt'ta AI'a "ASLA başka marka önerme" talimatı verilmiş.

---

## 9. GÜVENLİK

- **Helmet.js:** Production'da aktif (CSP kapalı)
- **Rate Limiting:** 15 dakikada 100 mesaj, admin login 5 deneme
- **CORS:** Production'da sadece izin verilen originler
- **bcrypt:** Admin şifreleri hash'li
- **HTTPS:** Production'da zorunlu redirect
- **Blacklist:** İntihar, şiddet vb. kelime filtresi
- **Avatar URL doğrulama:** Sadece güvenilir domainlerden (google, gravatar)
- **Trust Proxy:** Coolify/Nginx arkasında çalışma

---

## 10. TAMAMLANAN ÖZELLİKLER (Tarihsel Sıra)

### Faz 1-6 (Önceden Tamamlanmış)
- [x] Node.js/Express backend + MongoDB
- [x] OpenAI GPT-4o API entegrasyonu
- [x] Coolify deployment + SSL + Domain
- [x] ChatGPT tarzı modern arayüz (responsive, tema)
- [x] Sohbet geçmişi, mod seçimi, hava durumu analizi
- [x] Ürün önerisi (Mini RAG)
- [x] Güvenlik: Helmet, rate-limit, CORS, bcrypt, XSS koruması
- [x] Google OAuth (One Tap + popup + mobil redirect)
- [x] Visitor → Google hesap sohbet taşıma
- [x] Admin paneli (prompt yönetimi, model parametreleri, istatistikler)

### Yapılacaklar Planından Tamamlanan (Şubat 2026)
- [x] Push Notification Altyapısı (Firebase Admin SDK + FCM)
- [x] Günlük Cilt Bakımı Hatırlatıcısı (node-cron)
- [x] Su İçme Hatırlatıcısı (saat başı, interval bazlı)
- [x] Özelleştirilebilir Hatırlatma Saatleri (sabah/akşam/interval UI)
- [x] Kullanıcı Profil Sayfası (modal, istatistikler, üyelik bilgileri)
- [x] Cilt Tipi Anketi (5 tip, 8 sorun)
- [x] Yaş/Cinsiyet/Bölge Bilgisi (radio + select)
- [x] Alerji ve Hassasiyet Kaydı (7 alerjen + 6 tetikleyici)
- [x] Kişiselleştirilmiş AI Yanıtları (profilePrompt injection)

---

## 11. SIRADA BEKLEYEN GÖREVLER

Proje planlamasına göre sıradaki görevler:

### Analitik & Raporlama
- [ ] Google Analytics 4 Entegrasyonu
- [ ] Kullanıcı Davranış Takibi
- [ ] Sohbet İstatistikleri Dashboard
- [ ] Popüler Sorular Analizi
- [ ] Admin Raporlama Paneli

### Fotoğraf & Görsel Analiz
- [ ] Fotoğraf Yükleme Özelliği
- [ ] GPT-4 Vision Entegrasyonu
- [ ] Cilt Analizi (Fotoğraftan)
- [ ] Güvenli Görsel Depolama
- [ ] Görsel Geçmişi ve Karşılaştırma

### Çoklu Dil
- [ ] i18n Altyapısı
- [ ] İngilizce Çeviri
- [ ] Arapça Çeviri (RTL)
- [ ] Dil Seçici UI
- [ ] AI Yanıtlarında Çoklu Dil

### Mobil Uygulama (PWA → Native)
- [ ] PWA Manifest & Service Worker
- [ ] Offline Mod Desteği
- [ ] Store Publish
- [ ] Native Push Notifications
- [ ] Biometric Login

### Topluluk & Monetizasyon
- [ ] Topluluk Forumu
- [ ] Tarif/Rutin Paylaşımı
- [ ] Kullanıcı Yorumları
- [ ] Liderlik Tablosu
- [ ] Premium AI Modeli
- [ ] Sınırsız Sohbet Paketi
- [ ] Özel Danışman Modu

---

## 12. VERSİYON GEÇMİŞİ

| Versiyon | Tarih | Değişiklikler |
|----------|-------|---------------|
| v2.9 | 10 Şubat 2026 | Profil anketi (4 adım), AI kişiselleştirme, survey JS |
| v2.8 | 9 Şubat 2026 | Profil sayfası modal, istatistikler, survey HTML+CSS |
| v2.7 | ~8 Şubat 2026 | Push notification sistemi, hatırlatıcılar |
| v2.5 | ~6 Şubat 2026 | Google OAuth mobil fix, style güncellemeleri |

---

## 13. HIZLI REFERANS: KODDA NEREDE NE VAR

### server.js Haritası
| Satır Aralığı | İçerik |
|----------------|--------|
| 1-100 | Imports, Firebase Admin init, env setup |
| 100-200 | Express config, Helmet, CORS, rate-limit |
| 200-240 | Chat Schema |
| 240-285 | AdminSettings Schema |
| 285-315 | User Schema (profile dahil) |
| 315-350 | PushSubscription Schema |
| 350-420 | Mini RAG (SHADLESS_PRODUCTS) |
| 420-500 | Blacklist, Shopify middleware |
| 500-710 | handleChat (legacy), handleUnifiedChatAPI (mesaj handler, profil prompt dahil) |
| 1000-1300 | Google OAuth routes (callback, code, one-tap, migrate) |
| 1300-1400 | User profile API (PUT + GET /api/user/profile) |
| 1400-1900 | Push API (subscribe, unsubscribe, preferences, broadcast) |
| 1900-2100 | Legacy chat routes |
| 2100-2350 | Admin routes (login, settings, stats) |
| 2350-2450 | Reminder scheduler (cron jobs) |
| 2450-2459 | app.listen |

### main.js Haritası
| Satır Aralığı | İçerik |
|----------------|--------|
| 1-40 | Config, state variables, getUserId |
| 40-160 | Google Auth (popup, handleSignIn, migrate) |
| 160-310 | Login state, updateUserUI, initGoogleAuth |
| 310-500 | Push notifications (init, token, permission, UI) |
| 500-660 | Reminder settings (load, save, init) |
| 660-780 | Profile page (open/close modal, loadStats) |
| 780-850 | initProfilePage + survey button init |
| 850-1060 | Survey modal (open/close, step nav, data collect, save, load existing) |
| 1060-1090 | showInAppNotification |
| 1090-1200 | DOM elements, mobile menu, theme |
| 1200-1500 | Chat operations (load, send, render, format) |
| 1500-1600 | Weather modal |
| 1600-1660 | Input handling, event listeners, init |

---

## 14. TROUBLESHOOTING

### "502 Bad Gateway" Coolify'da
1. Container logları kontrol: `docker logs <id>`
2. `app.listen(PORT, '0.0.0.0', ...)` olduğundan emin ol
3. PORT env var 3000 mi?
4. MongoDB bağlantısı başarılı mı?

### Push Bildirim Çalışmıyor
1. `firebase-messaging-sw.js` public'te mi?
2. FIREBASE_* env var'lar doğru mu?
3. `Notification.permission` ne diyor?
4. Token alınabiliyor mu? (console log kontrol)

### Google Login Çalışmıyor
1. `GOOGLE_CLIENT_ID` ve `GOOGLE_CLIENT_SECRET` doğru mu?
2. Authorized redirect URIs'de `https://singapur.semihcankadioglu.com.tr/auth/google/callback` var mı?
3. Mobilde popup engelleniyor olabilir → redirect yöntemi kullanılmalı

### AI Profil Kişiselleştirme Çalışmıyor
1. User.profile.isProfileComplete === true mi? (DB kontrol)
2. userId formatı: frontend `google_<id>` gönderiyor, backend `google_` prefix'ini strip ediyor
3. profilePrompt oluşturuluyor mu? (server loglarına bak)

---

*Bu dosya her major değişiklikte güncellenmelidir.*
