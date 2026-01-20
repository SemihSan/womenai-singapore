# Women AI Backend - Sistem Dokümantasyonu

## 📋 İçindekiler
1. [Genel Bakış](#genel-bakış)
2. [Sistem Mimarisi](#sistem-mimarisi)
3. [Backend Yapısı](#backend-yapısı)
4. [MongoDB Veritabanı](#mongodb-veritabanı)
5. [OpenAI API Entegrasyonu](#openai-api-entegrasyonu)
6. [Humanizer Özelliği](#humanizer-özelliği)
7. [Admin Panel](#admin-panel)
8. [Deployment Süreci](#deployment-süreci)
9. [API Endpoints](#api-endpoints)
10. [Güvenlik](#güvenlik)
11. [Sorun Giderme](#sorun-giderme)

---

## 🎯 Genel Bakış

Women AI Backend, kadınlara yönelik cilt bakımı, motivasyon ve beslenme konularında doğal Türkçe dil kullanarak yardımcı olan bir yapay zeka chatbot sistemidir. Sistem, Mert Group bünyesinde geliştirilmiş gibi sunulur ve sadece **Shadeless** marka ürünlerini önerir.

### Temel Özellikler
- 🗣️ **Doğal Türkçe Konuşma**: Günlük dilde, samimi ve içten yanıtlar
- 🧴 **Sadece Shadeless Ürünleri**: Asla dış marka önerisi yapmaz
- 🤖 **GPT-4o Mini**: Hızlı ve ekonomik AI modeli
- 🛡️ **Rate Limiting**: DDoS ve spam koruması
- 👨‍💼 **Admin Panel**: Tüm ayarları yönetme
- 📊 **MongoDB**: Konuşma geçmişi ve ayarlar
- 🎭 **3 Mod**: Bakım, Motivasyon, Beslenme

---

## 🏗️ Sistem Mimarisi

```
┌─────────────────┐
│  Shopify Store  │
│   (Frontend)    │
└────────┬────────┘
         │
         │ HTTPS
         ▼
┌─────────────────┐
│  Nginx Reverse  │
│     Proxy       │
└────────┬────────┘
         │
         │ Port 3000
         ▼
┌─────────────────┐        ┌──────────────┐
│   Node.js App   │◄──────►│   MongoDB    │
│   (Express.js)  │        │   Database   │
└────────┬────────┘        └──────────────┘
         │
         │ API Calls
         ▼
┌─────────────────┐
│  OpenAI API     │
│   (GPT-4o)      │
└─────────────────┘
```

### Teknoloji Stack
- **Backend**: Node.js v22.11.0 + Express 5.1.0
- **Database**: MongoDB 7.0
- **AI Model**: OpenAI GPT-4o-mini
- **Deployment**: Coolify (Self-hosted) + DigitalOcean
- **Reverse Proxy**: Nginx
- **Domain**: women-ai-api.semihcankadioglu.com.tr

---

## 🔧 Backend Yapısı

### Dosya Yapısı
```
women-ai-backend-main/
├── server.js              # Ana backend server
├── admin-panel.html       # Admin panel UI
├── setup-admin.js         # İlk admin kurulum script
├── package.json           # NPM dependencies
├── .env                   # Environment variables
├── LOCALHOST.md           # Local development guide
└── README.md              # Genel README
```

### Ana Bağımlılıklar (package.json)
```json
{
  "dependencies": {
    "express": "^5.1.0",
    "mongoose": "^8.9.3",
    "express-rate-limit": "^7.5.0",
    "dotenv": "^16.4.7",
    "bcrypt": "^5.1.1"
  }
}
```

### Environment Variables (.env)
```bash
MONGODB_URI=mongodb://localhost:27017/women-ai
OPENAI_API_KEY=sk-proj-xxxxx
PORT=3000
ADMIN_USERNAME=admin
ADMIN_PASSWORD=hashed_password
```

---

## 💾 MongoDB Veritabanı

### Collections

#### 1. **adminsettings**
Admin paneli ayarları (sadece 1 dokuman)

```javascript
{
  _id: ObjectId,
  systemPrompt: String,          // Ana sistem promptu (humanizer + Mert Group)
  carePrompt: String,             // Bakım modu ekstra promptu
  motivationPrompt: String,       // Motivasyon modu promptu
  dietPrompt: String,             // Beslenme modu promptu
  temperature: Number,            // 0.6 (varsayılan)
  model: String,                  // "gpt-4o-mini"
  maxMessageLength: Number,       // 2000
  blacklist: [String],            // Yasaklı kelimeler
  rateLimitWindow: Number,        // 60000 ms (1 dakika)
  rateLimitMax: Number,           // 10 istek/dakika
  
  // Yeni OpenAI Parametreleri
  maxTokens: Number,              // null = sınırsız, önerilen: 500-1000
  frequencyPenalty: Number,       // 0-2 arası, tekrar azaltma (önerilen: 0.3-0.5)
  presencePenalty: Number,        // 0-2 arası, yeni konular (önerilen: 0.3-0.5)
  topP: Number,                   // 0-1 arası, çeşitlilik (varsayılan: 1)
  
  createdAt: Date,
  updatedAt: Date
}
```

#### 2. **chats**
Kullanıcı sohbet oturumları

```javascript
{
  _id: ObjectId,
  userId: String,                 // Shopify müşteri ID
  messages: [
    {
      role: String,               // "user" veya "assistant"
      content: String,            // Mesaj içeriği
      timestamp: Date
    }
  ],
  mode: String,                   // "care", "motivation", "diet"
  createdAt: Date,
  updatedAt: Date
}
```

#### 3. **adminusers**
Admin kullanıcıları (şifreler bcrypt ile hashlenmiş)

```javascript
{
  _id: ObjectId,
  username: String,               // "admin"
  password: String,               // bcrypt hash
  token: String,                  // Session token
  createdAt: Date
}
```

---

## 🤖 OpenAI API Entegrasyonu

### API Request Yapısı

```javascript
fetch('https://api.openai.com/v1/chat/completions', {
  method: 'POST',
  headers: {
    'Authorization': `Bearer ${OPENAI_API_KEY}`,
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    model: 'gpt-4o-mini',
    messages: [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: 'Cildim çok kuru ne yapmalıyım?' },
      { role: 'assistant', content: 'Ayyy anlıyorum canım 😔...' }
    ],
    temperature: 0.6,
    max_tokens: 500,                    // Yanıt uzunluğu limiti
    frequency_penalty: 0.3,             // Tekrar azaltma
    presence_penalty: 0.3,              // Yeni konular
    top_p: 1                            // Çeşitlilik kontrolü
  })
})
```

### OpenAI Parametreleri Açıklaması

#### **temperature** (0.0 - 2.0)
- **Ne İşe Yarar**: AI'ın yaratıcılığını ve rastgeleliğini kontrol eder
- **0**: Deterministik, her zaman aynı cevap
- **0.6**: Dengeli, hem tutarlı hem yaratıcı (bizim değer)
- **2.0**: Çok yaratıcı ama tutarsız

#### **max_tokens** (null = sınırsız)
- **Ne İşe Yarar**: Yanıtın maksimum uzunluğunu sınırlar
- **500-800**: Kısa ve öz yanıtlar (mobil için ideal)
- **1000-2000**: Orta uzunlukta detaylı yanıtlar
- **null**: Sınırsız (uzun yanıtlar, maliyet artışı)

#### **frequency_penalty** (-2.0 to 2.0)
- **Ne İşe Yarar**: Aynı kelimelerin/cümlelerin tekrar edilmesini önler
- **0**: Normal davranış
- **0.3-0.5**: Ürün isimlerinin tekrar edilmesini azaltır ✅
- **1.0+**: Aşırı çeşitlilik, tutarsızlık

**Örnek Kullanım**:
```
Frequency Penalty = 0:
"Serum Step-2 kullan, Serum Step-2 harika, Serum Step-2 öneririm"

Frequency Penalty = 0.5:
"Serum Step-2 kullan, leke serumu harika, spot tedavisi öneririm"
```

#### **presence_penalty** (-2.0 to 2.0)
- **Ne İşe Yarar**: Yeni konuları keşfetmeyi teşvik eder
- **0**: Normal davranış
- **0.3-0.5**: Aynı noktada takılmayı önler ✅
- **1.0+**: Çok fazla konu atlama

**Örnek Kullanım**:
```
Presence Penalty = 0:
"Nemlendirici kullan, nemlendirici önemli, nemlendirici al..."

Presence Penalty = 0.5:
"Nemlendirici kullan, ayrıca güneş kremi de ekle, su tüketimi artır..."
```

#### **top_p** (0.0 - 1.0)
- **Ne İşe Yarar**: Nucleus sampling, temperature'e alternatif
- **1**: Varsayılan, tüm olasılıklar dahil
- **0.9**: En olası %90'lık dilim kullanılır
- **0.5**: Daha dar, daha tutarlı

⚠️ **NOT**: `temperature` ve `top_p` genelde birlikte kullanılmaz. Birini kullan.

---

## 💬 Humanizer Özelliği

Sistem, kadın kullanıcılarla günlük konuşma havasında, samimi ve doğal bir dilde iletişim kurar.

### Konuşma Özellikleri

#### ✅ Kullanılan İfadeler
- **Samimi Sözcükler**: "valla", "yaa", "canım", "tatlım", "ayy"
- **Emoji Kullanımı**: 😊, 😔, 💕, ✨, 🥰
- **Günlük Dil**: "nolcak", "yapmalıyız", "bi bakıyım"
- **Empati**: "Çok iyi anlıyorum seni...", "Ayyy ne güzel..."

#### ❌ Kullanılmayan İfadeler
- ~~Resmi dil~~
- ~~"Size yardımcı olabilirim"~~
- ~~"Memnuniyetle cevaplıyorum"~~
- ~~Robotik ifadeler~~

### Örnek Konuşmalar

**KÖTÜ (Eski Sistem)**:
```
Kullanıcı: "cildim çok kuru napmalıyım ya"
Eski Bot: "Kuru cilt için nemlendirici kullanmanızı öneririm. 
           Ayrıca bol su tüketin."
```

**İYİ (Yeni Humanizer)**:
```
Kullanıcı: "cildim çok kuru napmalıyım ya"
Yeni Bot: "Ayyy anlıyorum canım 😔 Kuru cilt gerçekten rahatsız 
           edici olabiliyor. Bak sana süper bir önerim var! 
           Shadeless'ın Hydration Serum'u tam senlik olur valla 💕 
           Bir de günde 2-3 litre su içmeyi unutma tatlım ✨"
```

### System Prompt Yapısı

Prompt **İngilizce kurallar** + **Türkçe örnekler** şeklinde yapılandırılmıştır.

```markdown
[IDENTITY / SCOPE — EN]
You are a women-focused care & lifestyle assistant developed by the Mert Group team.
NEVER mention OpenAI, GPT, or any external AI company.
Always say you were developed by "Mert Group yazılımcı ekibi".

[TONE & STYLE — EN]
Use casual, warm, colloquial Turkish.
Use feminine-friendly language: "valla", "canım", "tatlım", "ayy"...

[PRODUCT RULES — EN]
ONLY recommend Shadeless brand products.
NEVER recommend: La Roche-Posay, CeraVe, Neutrogena, Bioderma...
NEVER tell users to "research online" or "buy from pharmacy"...

[TR STYLE EXAMPLES — TR]
Kullanıcı: "cildim çok kuru napmalıyım ya"
Asistan: "Ayyy anlıyorum canım 😔 Kuru cilt çok sinir bozucu..."
```

---

## 🎛️ Admin Panel

### Erişim
**URL**: https://women-ai-api.semihcankadioglu.com.tr/admin-panel.html

**Giriş Bilgileri**: `.env` dosyasında tanımlı
```
Username: admin
Password: [bcrypt hash]
```

### Özellikler

#### 1. **İstatistikler**
- 💬 Toplam Sohbet Sayısı
- 📨 Toplam Mesaj Sayısı  
- ⏱️ Sunucu Uptime

#### 2. **AI Model Ayarları**
- **Model Seçimi**: GPT-4o-mini, GPT-4o, GPT-4-turbo, GPT-3.5-turbo
- **Maks. Mesaj Uzunluğu**: Kullanıcı mesaj karakteri limiti (varsayılan: 2000)
- **Temperature**: 0-2 arası, yaratıcılık (varsayılan: 0.6)
- **Frequency Penalty**: -2 ile 2 arası, tekrar azaltma (önerilen: 0.3-0.5)
- **Presence Penalty**: -2 ile 2 arası, yeni konular (önerilen: 0.3-0.5)
- **Top P**: 0-1 arası, çeşitlilik (varsayılan: 1)
- **Max Tokens**: 0-4000, yanıt uzunluğu (önerilen: 500-1000)

#### 3. **Prompt Yönetimi**
- **Ana Sistem Promptu**: AI'ın temel kişiliği ve kuralları
- **Bakım Modu Promptu**: Cilt bakımı odaklı ek talimatlar
- **Motivasyon Modu Promptu**: Motivasyon ve ruh hali desteği
- **Beslenme Modu Promptu**: Sağlıklı beslenme önerileri

#### 4. **Kara Liste**
Yasaklı kelimeler ve markalar:
- La Roche-Posay
- CeraVe
- Neutrogena
- Bioderma
- Vichy
- vb.

#### 5. **Rate Limiting**
- **Window**: İstek penceresi (ms) - varsayılan: 60000 (1 dakika)
- **Max**: Pencere başına maksimum istek - varsayılan: 10

---

## 🚀 Deployment Süreci

### 1. Local Development

```bash
# Dependencies kurulumu
npm install

# MongoDB başlat
mongod --dbpath ./data

# Environment variables
cp .env.example .env
nano .env

# Admin kullanıcı oluştur
node setup-admin.js

# Server başlat
npm start
```

Server: `http://localhost:3000`

### 2. Production (Coolify + DigitalOcean)

#### Git Push
```bash
git add .
git commit -m "Update system"
git push origin main
```

#### Coolify Auto-Deploy
1. Coolify otomatik git değişikliklerini algılar
2. Docker container rebuild yapar
3. Node.js app yeniden başlatılır
4. Nginx reverse proxy ile yayınlanır

#### MongoDB Güncelleme (Gerekirse)
```bash
# Coolify MongoDB terminaline gir
mongosh

# Tüm ayarları sıfırla (yeni defaultları kullan)
db.adminsettings.deleteMany({})
exit

# Backend'i restart et (Coolify'dan)
```

#### Nginx Konfigürasyonu
```nginx
server {
    listen 443 ssl http2;
    server_name women-ai-api.semihcankadioglu.com.tr;

    ssl_certificate /etc/letsencrypt/live/domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/domain/privkey.pem;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

### 3. Deployment Checklist

- [ ] `.env` dosyası oluşturuldu
- [ ] MongoDB bağlantısı çalışıyor
- [ ] OpenAI API key geçerli
- [ ] Admin kullanıcı oluşturuldu
- [ ] Nginx reverse proxy ayarlandı
- [ ] SSL sertifikası aktif
- [ ] Rate limiting test edildi
- [ ] Admin panel erişilebilir
- [ ] Shopify entegrasyonu test edildi

---

## 🔌 API Endpoints

### Public Endpoints

#### POST `/chat`
Kullanıcı mesajı gönder, AI yanıtı al

**Request Body**:
```json
{
  "userId": "shopify-12345",
  "message": "Cildim çok kuru ne yapmalıyım?",
  "mode": "care"
}
```

**Response**:
```json
{
  "reply": "Ayyy anlıyorum canım 😔 Kuru cilt gerçekten...",
  "chatId": "mongodb-objectid"
}
```

**Rate Limit**: 10 requests/minute per IP

---

### Admin Endpoints (x-admin-token required)

#### POST `/admin/login`
Admin girişi, token al

**Request Body**:
```json
{
  "username": "admin",
  "password": "your-password"
}
```

**Response**:
```json
{
  "token": "jwt-token-here"
}
```

#### GET `/admin/stats`
Sistem istatistikleri

**Response**:
```json
{
  "totalChats": 1523,
  "totalMessages": 4569,
  "uptime": 86400
}
```

#### GET `/admin/settings`
Tüm ayarları getir

**Response**:
```json
{
  "systemPrompt": "...",
  "temperature": 0.6,
  "frequencyPenalty": 0.3,
  ...
}
```

#### PUT `/admin/settings`
Ayarları güncelle

**Request Body**:
```json
{
  "temperature": 0.7,
  "frequencyPenalty": 0.5,
  "maxTokens": 800,
  "systemPrompt": "..."
}
```

#### POST `/admin/logout`
Admin oturumu kapat

---

## 🔒 Güvenlik

### 1. Rate Limiting
```javascript
const rateLimit = rateLimit({
  windowMs: 60000,        // 1 dakika
  max: 10,                 // 10 istek/dakika
  message: 'Çok fazla istek...',
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false }
})
```

### 2. Admin Authentication
- Bcrypt password hashing
- JWT token-based sessions
- Token expiration (24 saat)

### 3. Input Sanitization
- Mesaj uzunluğu limiti: 2000 karakter
- Blacklist keyword kontrolü
- MongoDB injection prevention (Mongoose)

### 4. HTTPS
- SSL/TLS encryption (Let's Encrypt)
- Nginx reverse proxy
- HSTS headers

---

## 🐛 Sorun Giderme

### Problem: MongoDB bağlantısı kopuyor
**Çözüm**:
```bash
# MongoDB servisini kontrol et
systemctl status mongod

# Yeniden başlat
systemctl restart mongod

# Connection string kontrol
echo $MONGODB_URI
```

### Problem: OpenAI API "Too many requests"
**Çözüm**:
- Rate limiting artırılabilir
- OpenAI quota kontrol: https://platform.openai.com/usage
- Model değiştir: GPT-4o-mini → GPT-3.5-turbo

### Problem: Admin panel açılmıyor
**Çözüm**:
```bash
# Nginx config test
nginx -t

# Nginx restart
systemctl restart nginx

# Admin token kontrol
node setup-admin.js
```

### Problem: AI eski promptu kullanıyor
**Çözüm**:
```bash
# MongoDB'yi temizle
mongosh --eval "db.adminsettings.deleteMany({})"

# Backend restart (Coolify'dan)

# Admin panelden yeni ayarları kaydet
```

### Problem: Deployment başarısız
**Kontrol Listesi**:
1. `package.json` syntax hatası var mı?
2. `.env` dosyası production'da var mı?
3. Coolify build logs'u incele
4. Port 3000 kullanımda mı?

---

## 📊 Performans Metrikleri

### Response Times (Ortalama)
- **/chat endpoint**: 1-3 saniye
- **/admin/settings GET**: <100ms
- **/admin/settings PUT**: 200-500ms

### OpenAI API Costs
- **GPT-4o-mini**: $0.15 / 1M input tokens, $0.60 / 1M output tokens
- **Ortalama chat maliyeti**: ~$0.0005 (0.5 cent)
- **Aylık 10,000 mesaj**: ~$5

### Database Size
- **Chat collection**: ~1KB per chat
- **10,000 chats**: ~10MB
- **Recommended**: Weekly backup

---

## 📞 Destek ve İletişim

**Geliştirici**: Semih Can Kadıoğlu  
**Email**: semih@example.com  
**Domain**: women-ai-api.semihcankadioglu.com.tr

---

## 📝 Değişiklik Geçmişi

### v2.0.0 (23 Aralık 2025)
- ✅ OpenAI advanced parameters eklendi
  - frequency_penalty (tekrar azaltma)
  - presence_penalty (yeni konular)
  - max_tokens (yanıt uzunluğu)
  - top_p (çeşitlilik)
- ✅ Admin panel UI güncellendi
- ✅ MongoDB schema genişletildi

### v1.5.0 (Aralık 2025)
- ✅ Humanizer özelliği eklendi
- ✅ Mert Group branding
- ✅ Sadece Shadeless ürün önerileri
- ✅ Temperature 0.6'ya yükseltildi
- ✅ İngilizce prompt + Türkçe örnekler

### v1.0.0 (İlk Versiyon)
- ✅ Temel chatbot yapısı
- ✅ MongoDB entegrasyonu
- ✅ Admin panel
- ✅ Rate limiting
- ✅ 3 mod: Bakım, Motivasyon, Beslenme

---

## 🎓 Kaynaklar

- [OpenAI API Docs](https://platform.openai.com/docs)
- [Express.js Documentation](https://expressjs.com/)
- [MongoDB Manual](https://www.mongodb.com/docs/)
- [Coolify Documentation](https://coolify.io/docs)

---

**Son Güncelleme**: 23 Aralık 2025  
**Versiyon**: 2.0.0
