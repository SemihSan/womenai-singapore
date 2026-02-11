// server.js
require('dotenv').config();

const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');
const path = require('path');

// node-cron'u lazy load yap (optional dependency)
let cron = null;
try {
  cron = require('node-cron');
  console.log('✅ node-cron yüklendi');
} catch (err) {
  console.log('⚠️ node-cron yüklenemedi, scheduler devre dışı:', err.message);
}

// Firebase Admin SDK Initialize
let firebaseInitialized = false;
try {
  let serviceAccount;

  // Önce environment variable'dan dene (Coolify için)
  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    let envValue = process.env.FIREBASE_SERVICE_ACCOUNT;

    // Debug: İlk 50 karakteri göster
    console.log('🔍 Firebase env ilk 50 char:', envValue.substring(0, 50));
    console.log('🔍 Firebase env ilk char code:', envValue.charCodeAt(0));

    // Coolify bazen başa/sona tırnak ekleyebiliyor, temizle
    envValue = envValue.trim();

    // Çift tırnak temizle (nested olabilir)
    while ((envValue.startsWith('"') && envValue.endsWith('"')) ||
      (envValue.startsWith("'") && envValue.endsWith("'"))) {
      envValue = envValue.slice(1, -1);
    }

    // Escaped karakterleri düzelt (Coolify JSON'u escape ediyor)
    // \" -> " (escaped quotes)
    envValue = envValue.replace(/\\"/g, '"');
    // \\\\ -> \\ (double escaped backslashes - for private_key \n sequences)  
    // Coolify: \n -> \\n, so we need to keep \n as literal for JSON.parse
    // Don't convert \n to actual newlines - JSON.parse handles \n escape sequences

    // Base64 encoded olabilir mi kontrol et
    if (!envValue.startsWith('{')) {
      try {
        const decoded = Buffer.from(envValue, 'base64').toString('utf8');
        if (decoded.startsWith('{')) {
          envValue = decoded;
          console.log('📦 Firebase config: Base64 decoded');
        }
      } catch (e) {
        // Base64 değil, devam et
      }
    }

    console.log('🔍 Parse edilecek ilk 50 char:', envValue.substring(0, 50));

    serviceAccount = JSON.parse(envValue);

    // Coolify private_key içindeki \n'leri literal string olarak bırakıyor
    // PEM format için gerçek newline'lara çevirmemiz lazım
    if (serviceAccount.private_key && typeof serviceAccount.private_key === 'string') {
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    }

    console.log('📦 Firebase config: Environment variable');
  } else {
    // Yoksa dosyadan oku (local development için)
    const serviceAccountPath = path.join(__dirname, 'firebase-service-account.json');
    serviceAccount = require(serviceAccountPath);
    console.log('📦 Firebase config: JSON dosyası');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
  firebaseInitialized = true;
  console.log('✅ Firebase Admin SDK initialized');
} catch (err) {
  console.warn('⚠️ Firebase Admin SDK yüklenemedi:', err.message);
}

const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ALLOWED_ADMIN_SHOPS = (process.env.ALLOWED_ADMIN_SHOPS || '').split(',').filter(Boolean);

// node-fetch (Node 18+ için dinamik import)
const fetch = (...args) => import('node-fetch').then(({ default: fetch }) => fetch(...args));

const app = express();

// Trust proxy (Coolify/Nginx arkasında çalışıyoruz - sadece production'da)
if (IS_PRODUCTION) {
  app.set('trust proxy', true);
}

// Development modda Helmet'i kapat
if (!IS_PRODUCTION) {
  console.log('⚠️  Development mode: Güvenlik kontrolleri devre dışı');
} else {
  app.use(helmet({
    contentSecurityPolicy: false,
  }));
}

app.use(express.json());

// Statik dosyaları sun (index.html, style.css, main.js)
app.use(express.static(__dirname));

// Production'da HTTPS zorunlu
if (IS_PRODUCTION) {
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https') {
      return res.redirect('https://' + req.headers.host + req.url);
    }
    next();
  });
}

/* =========================================================
  0) CORS - Development'ta tüm originlere izin ver
  ========================================================= */
if (IS_PRODUCTION) {
  const allowedOrigins = [
    'https://womenai.semihcankadioglu.com.tr',
    'https://www.womenai.semihcankadioglu.com.tr',
    'https://singapur.semihcankadioglu.com.tr',
    'https://www.singapur.semihcankadioglu.com.tr',
  ];

  app.use((req, res, next) => {
    // Admin endpoint'leri için CORS kontrolünü atla
    if (req.path.startsWith('/admin')) {
      res.header('Access-Control-Allow-Origin', '*');
      res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      res.header('Access-Control-Allow-Headers', 'Content-Type, x-admin-token');
      if (req.method === 'OPTIONS') {
        return res.sendStatus(200);
      }
      return next();
    }

    // Diğer endpoint'ler için normal CORS
    cors({
      origin: function (origin, cb) {
        if (!origin) return cb(null, true);
        if (allowedOrigins.includes(origin)) return cb(null, true);
        return cb(new Error('Not allowed by CORS'));
      },
      credentials: true,
    })(req, res, next);
  });

  app.use((err, req, res, next) => {
    if (err && err.message === 'Not allowed by CORS') {
      return res.status(403).json({ error: 'Erişim reddedildi (CORS)' });
    }
    next(err);
  });
} else {
  // Development: Tüm originlere izin ver
  app.use(cors());
  console.log('⚠️  CORS: Tüm originlere izin veriliyor');
}

const chatLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Çok hızlı mesaj gönderiyorsun! (15 dakikada 100 limit)' },
  standardHeaders: true,
  legacyHeaders: false,
  validate: { trustProxy: false }, // trust proxy validation'ı kapat
});

const PORT = process.env.PORT || 3000;

/* =========================================================
  1) MongoDB
  ========================================================= */
const mongoUri = process.env.MONGODB_URI || 'mongodb://127.0.0.1:27017/women_ai_chat';

mongoose
  .connect(mongoUri) // driver v4+ için useNewUrlParser/useUnifiedTopology gereksiz
  .then(() => console.log('✅ MongoDB bağlantısı başarılı'))
  .catch((err) => console.error('❌ MongoDB bağlantı hatası:', err));

/* =========================================================
  2) Chat Schema
  ========================================================= */
const chatSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  title: { type: String, default: 'Yeni Sohbet' }, // Sohbet başlığı
  mode: { type: String, enum: ['care', 'motivation', 'diet'], default: 'care' }, // Mod
  isArchived: { type: Boolean, default: false }, // Arşivlenmiş mi
  isFavorite: { type: Boolean, default: false }, // Favori mi
  messages: [
    {
      role: { type: String, enum: ['user', 'assistant'], required: true },
      content: { type: String, required: true },
      timestamp: { type: Date, default: Date.now },
    },
  ],
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Güncelleme zamanını otomatik ayarla
chatSchema.pre('save', function (next) {
  this.updatedAt = new Date();
  next();
});

// İlk mesajdan başlık oluştur
chatSchema.methods.generateTitle = function () {
  if (this.messages.length > 0) {
    const firstUserMsg = this.messages.find(m => m.role === 'user');
    if (firstUserMsg) {
      // İlk 40 karakteri al
      this.title = firstUserMsg.content.substring(0, 40) + (firstUserMsg.content.length > 40 ? '...' : '');
    }
  }
};

const Chat = mongoose.model('Chat', chatSchema);

/* =========================================================
  2.1) Admin Settings Schema
  ========================================================= */
const adminSettingsSchema = new mongoose.Schema({
  systemPrompt: { type: String, default: '' },
  carePrompt: { type: String, default: '' },
  motivationPrompt: { type: String, default: '' },
  dietPrompt: { type: String, default: '' },
  temperature: { type: Number, default: 0.6, min: 0, max: 2 },
  model: { type: String, default: 'gpt-4o-mini' },
  maxMessageLength: { type: Number, default: 1000 },
  blacklist: { type: [String], default: [] },
  rateLimitWindow: { type: Number, default: 15 }, // dakika
  rateLimitMax: { type: Number, default: 100 },
  // OpenAI API parametreleri
  maxTokens: { type: Number, default: null }, // null = sınırsız
  frequencyPenalty: { type: Number, default: 0, min: -2, max: 2 }, // Tekrar azaltma
  presencePenalty: { type: Number, default: 0, min: -2, max: 2 }, // Yeni konulara geçiş
  topP: { type: Number, default: 1, min: 0, max: 1 }, // Temperature alternatifi
  updatedAt: { type: Date, default: Date.now },
});

const AdminSettings = mongoose.model('AdminSettings', adminSettingsSchema);

/* =========================================================
  2.2) Admin User Schema (bcrypt hash)
  ========================================================= */
const adminUserSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // bcrypt hash
  shopDomain: { type: String, required: true }, // Shopify shop domain
  sessionToken: { type: String, default: null },
  tokenExpiry: { type: Date, default: null },
});

// Şifre kaydetmeden önce hash'le
adminUserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (err) {
    next(err);
  }
});

// Şifre karşılaştırma method
adminUserSchema.methods.comparePassword = async function (candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const AdminUser = mongoose.model('AdminUser', adminUserSchema);

/* =========================================================
  2.3) User Schema (Google OAuth ile giriş yapan kullanıcılar)
  ========================================================= */
const userSchema = new mongoose.Schema({
  googleId: { type: String, required: true, unique: true },
  email: { type: String, required: true },
  name: { type: String, required: true },
  picture: { type: String },
  visitorId: { type: String }, // Eski visitor ID - geçiş için
  // Profil bilgileri (anket)
  profile: {
    skinType: { type: String, enum: ['kuru', 'yagli', 'karma', 'normal', 'hassas', ''], default: '' },
    skinConcerns: [{ type: String }], // ['akne', 'leke', 'kirisiklik', 'gozemek', 'kurulik', 'kizariklik']
    age: { type: String, enum: ['18-24', '25-34', '35-44', '45-54', '55+', ''], default: '' },
    gender: { type: String, enum: ['kadin', 'erkek', 'belirtmek-istemiyorum', ''], default: '' },
    region: { type: String, default: '' }, // Şehir
    allergies: [{ type: String }], // ['parfum', 'retinol', 'aha-bha', 'vitamin-c', 'niacinamide']
    sensitivities: [{ type: String }], // ['gunes', 'soguk', 'sicak', 'stres', 'hormon']
    isProfileComplete: { type: Boolean, default: false },
    completedAt: { type: Date },
  },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date, default: Date.now },
});

const User = mongoose.model('User', userSchema);

/* =========================================================
  2.4) Push Subscription Schema (Bildirim abonelikleri)
  ========================================================= */
const pushSubscriptionSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true }, // google_xxx veya visitor_xxx
  fcmToken: { type: String, required: true, unique: true },
  device: { type: String, default: 'web' }, // web, android, ios
  userAgent: { type: String },
  // Bildirim tercihleri
  preferences: {
    skincare: { type: Boolean, default: true }, // Cilt bakımı hatırlatıcı
    water: { type: Boolean, default: true }, // Su içme hatırlatıcı
    motivation: { type: Boolean, default: true }, // Motivasyon bildirimleri
    news: { type: Boolean, default: true }, // Yeni özellik duyuruları
  },
  // Hatırlatma saatleri
  reminderTimes: {
    morning: { type: String, default: '08:00' }, // Sabah bakımı
    evening: { type: String, default: '21:00' }, // Akşam bakımı
    waterInterval: { type: Number, default: 2 }, // Saat aralığı
  },
  timezone: { type: String, default: 'Europe/Istanbul' },
  isActive: { type: Boolean, default: true },
  createdAt: { type: Date, default: Date.now },
  lastNotification: { type: Date },
});

const PushSubscription = mongoose.model('PushSubscription', pushSubscriptionSchema);

/* =========================================================
  2.5) Activity Log Schema (Kullanıcı Davranış Takibi)
  ========================================================= */
const activityLogSchema = new mongoose.Schema({
  userId: { type: String, required: true, index: true },
  sessionId: { type: String, required: true, index: true },
  event: { type: String, required: true, index: true },
  category: {
    type: String,
    enum: ['navigation', 'interaction', 'feature', 'engagement', 'error'],
    default: 'interaction',
  },
  data: { type: mongoose.Schema.Types.Mixed, default: {} },
  page: { type: String, default: '' },
  duration: { type: Number, default: 0 }, // ms
  device: {
    type: { type: String, default: 'desktop' },
    browser: { type: String, default: '' },
    screenWidth: { type: Number },
    screenHeight: { type: Number },
  },
  createdAt: { type: Date, default: Date.now, index: true, expires: 7776000 }, // 90 gün TTL
});

// Compound index for efficient queries
activityLogSchema.index({ userId: 1, createdAt: -1 });
activityLogSchema.index({ event: 1, createdAt: -1 });
activityLogSchema.index({ category: 1, createdAt: -1 });

const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

/* =========================================================
  3) Mini RAG - ürünler
  ========================================================= */
const SHADLESS_PRODUCTS = [
  {
    id: 'cream-cleanser',
    name: 'Cream Cleanser',
    url: 'https://shadeless.cn/products/cleanser',
    summary: 'Cildi kurutmadan nazikçe temizleyen, krem-köpük yapıdaki günlük temizleyici.',
    tags: ['temizleyici', 'yüz temizleme', 'kuru cilt', 'hassas cilt', 'nazik temizlik', 'günlük rutin'],
  },
  {
    id: 'soothing-toner',
    name: 'Soothing Toner',
    url: 'https://shadeless.cn/products/soothing-toner',
    summary: 'Temizleme sonrası cildi yatıştıran, hafif, serumu daha iyi emdirmeye yardımcı tonik.',
    tags: ['tonik', 'toner', 'hassasiyet', 'kızarıklık', 'nem', 'serum öncesi'],
  },
  {
    id: 'step1-serum',
    name: 'Serum Step-1',
    url: 'https://shadeless.cn/collections/3-steps-serums/products/serum-step-1',
    summary: 'İlk adım serum: doku yenileme, gözenekleri daha düzgün gösterme, tonu aydınlatma ve nem desteği.',
    tags: ['step1', 'gözenek', 'pürüzlü doku', 'lekeler', 'ton eşitsizliği', 'donuk cilt', 'ışıltı'],
  },
  {
    id: 'step2-serum',
    name: 'Serum Step-2',
    url: 'https://shadeless.cn/collections/3-steps-serums/products/serum-step-2',
    summary: 'Ton eşitsizliği, kızarıklık, matlık ve gözenek görünümünü hedefleyen düzeltici serum.',
    tags: ['step2', 'leke', 'hiperpigmentasyon', 'kızarıklık', 'ton eşitleme', 'yağ dengesi', 'gözenek'],
  },
  {
    id: 'step3-serum',
    name: 'Serum Step-3',
    url: 'https://shadeless.cn/collections/3-steps-serums/products/serum-step-3',
    summary: '56% aktif içerikli yoğun serum: ince çizgi, sıkılık ve ışıltı için güçlendirilmiş bakım.',
    tags: ['step3', 'anti-aging', 'kırışıklık', 'sıkılaşma', 'kolajen', 'yoğun bakım', 'ışıltı', 'elastikiyet'],
  },
  {
    id: 'peptide-mask',
    name: 'Facial Skincare Peptide Mask',
    url: 'https://shadeless.cn/products/facial-skincare-mask',
    summary: 'Peptid bazlı maske: hızlı ışıltı, dolgunluk, nem ve daha pürüzsüz görünüm için destek.',
    tags: ['maske', 'peptid', 'yoğun nem', 'ince çizgi', 'elastikiyet', 'özel gün'],
  },
  {
    id: '3-steps-set',
    name: '3-Steps Serums Set',
    url: 'https://shadeless.cn/collections/3-steps-serums',
    summary: 'Hazırlama, düzeltme ve güçlendirme adımlarını bir arada sunan tam set.',
    tags: ['set', 'tam rutin', '3 adım', 'ton eşitsizliği', 'yaşlanma', 'lekeler', 'komple bakım'],
  },
];

function findRelevantProducts(userMessage = '') {
  const text = userMessage.toLowerCase();

  const scored = SHADLESS_PRODUCTS.map((p) => {
    let score = 0;
    for (const tag of p.tags) {
      const t = tag.toLowerCase();
      if (text.includes(t)) { score += 3; continue; }
      const words = t.split(' ').filter((w) => w.length > 3);
      if (words.some((w) => text.includes(w))) score += 1;
    }
    return { product: p, score };
  });

  return scored
    .filter((x) => x.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 3)
    .map((x) => x.product);
}

/* =========================================================
  4) Basit blacklist
  ========================================================= */
const BLACKLIST = ['intihar', 'intihar et', 'öldür', 'bomb', 'bomba', 'yasadışı', 'tecavüz', 'zarar ver'];

function isAllowed(text) {
  if (!text) return false;
  const t = text.toLowerCase();
  return !BLACKLIST.some((b) => t.includes(b));
}

/* =========================================================
  4.1) Shopify Admin Doğrulama Middleware
  ========================================================= */
function verifyShopifyAdmin(req, res, next) {
  // Development modda güvenlik kontrollerini atla
  if (!IS_PRODUCTION) {
    console.log('⚠️  Development modu: Shopify doğrulaması atlandı');
    req.shopDomain = req.query.shop || req.body.shop || 'localhost.myshopify.com';
    return next();
  }

  // Production: Shopify App Proxy'den gelen istekleri doğrula
  const shop = req.query.shop || req.body.shop;

  if (!shop) {
    return res.status(403).json({ error: 'Shopify shop bilgisi gerekli' });
  }

  // İzin verilen shop'ları kontrol et
  if (ALLOWED_ADMIN_SHOPS.length > 0 && !ALLOWED_ADMIN_SHOPS.includes(shop)) {
    console.warn(`🚫 İzinsiz admin erişimi: ${shop}`);
    return res.status(403).json({ error: 'Bu shop admin paneline erişemez' });
  }

  // Signature doğrulaması
  const signature = req.query.signature;
  if (!signature) {
    return res.status(401).json({ error: 'Shopify signature gerekli' });
  }

  const secret = process.env.SHOPIFY_APP_SECRET;
  if (!secret) {
    console.error('❌ SHOPIFY_APP_SECRET tanımlı değil!');
    return res.status(500).json({ error: 'Sunucu yapılandırma hatası' });
  }

  // Query parametrelerini doğrula
  const entries = Object.entries(req.query)
    .filter(([k]) => k !== 'signature')
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : v}`);

  const toVerify = entries.sort((a, b) => a.localeCompare(b)).join('');
  const calculated = crypto.createHmac('sha256', secret).update(toVerify).digest('hex');

  const a = Buffer.from(calculated, 'utf8');
  const b = Buffer.from(String(signature), 'utf8');

  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(401).json({ error: 'Geçersiz Shopify signature' });
  }

  req.shopDomain = shop;
  next();
}

/* =========================================================
  4.2) Admin Session Auth Middleware
  ========================================================= */
async function adminAuthMiddleware(req, res, next) {
  const token = req.headers['x-admin-token'];
  if (!token) {
    return res.status(401).json({ error: 'Token gerekli' });
  }

  try {
    const admin = await AdminUser.findOne({
      sessionToken: token,
      tokenExpiry: { $gt: new Date() },
    });

    if (!admin) {
      return res.status(401).json({ error: 'Geçersiz veya süresi dolmuş token' });
    }

    req.adminUser = admin;
    next();
  } catch (err) {
    console.error('Auth error:', err);
    return res.status(500).json({ error: 'Auth hatası' });
  }
}

/* =========================================================
  5) Shopify App Proxy doğrulama (signature)
  - Shopify, App Proxy isteklerine query içine "signature" ekler.
  - Bunu app secret ile HMAC-SHA256 doğruluyoruz.
  - Parametreleri signature hariç al -> "key=value" olarak sırala -> join('') -> HMAC-SHA256
  ========================================================= */
function verifyShopifyAppProxy(req, res, next) {
  const secret = process.env.SHOPIFY_APP_SECRET;
  if (!secret) {
    console.warn('⚠️ SHOPIFY_APP_SECRET yok. Proxy doğrulaması kapalı (önerilmez).');
    return next();
  }

  const signature = req.query.signature;
  if (!signature) {
    console.warn('⚠️ Shopify signature eksik');
    return res.status(401).json({ error: 'Yetkisiz (missing proxy signature)' });
  }

  // query objesini al, signature hariçle
  const entries = Object.entries(req.query)
    .filter(([k]) => k !== 'signature')
    .map(([k, v]) => `${k}=${Array.isArray(v) ? v.join(',') : v}`);

  // alfabetik sırala ve '&' olmadan birleştir (App Proxy için kritik)
  const toVerify = entries.sort((a, b) => a.localeCompare(b)).join('');

  const calculated = crypto
    .createHmac('sha256', secret)
    .update(toVerify)
    .digest('hex');

  // timing-safe compare
  const a = Buffer.from(calculated, 'utf8');
  const b = Buffer.from(String(signature), 'utf8');
  if (a.length !== b.length) {
    console.warn('⚠️ Signature uzunluk uyumsuzluğu');
    return res.status(401).json({ error: 'Yetkisiz (bad proxy signature)' });
  }
  if (!crypto.timingSafeEqual(a, b)) {
    console.warn('⚠️ Signature doğrulama başarısız');
    return res.status(401).json({ error: 'Yetkisiz (bad proxy signature)' });
  }

  console.log('✅ Shopify App Proxy signature doğrulandı');
  return next();
}

/* =========================================================
  6) Asıl chat handler (tek yerde dursun)
  ========================================================= */
async function handleChat(req, res) {
  try {
    // Admin ayarlarını al
    let settings = await AdminSettings.findOne();
    if (!settings) {
      // İlk çalıştırmada default ayarlar oluştur
      settings = new AdminSettings({
        systemPrompt: `Sen sadece kadınlara yönelik tasarlanmış özel bir bakım ve yaşam asistanısın. Mert Group bünyesindeki yazılımcı ekibi tarafından geliştirildin.

  KİMLİK & KİMSİN:
  - Mert Group'un yapay zeka destekli asistanısın
  - Özel olarak kadın sağlığı ve güzellik için tasarlandın
  - Hangi altyapı/teknoloji kullandığını ASLA söyleme (OpenAI, GPT vb. bahsetme)
  - Kendini tanıtırken sadece "Mert Group ekibi tarafından geliştirilmiş yapay zeka asistanı" de

  KONUŞMA DİLİ & TON:
  - Günlük Türkçe konuşma dili kullan: "valla", "bence", "canım", "ayy", "ya" gibi
  - "Yapmalısınız" yerine "yapabilirsin", "denersin", "bak derim" de
  - Samimi ama saygılı ol (argo/küfür yok)
  - Emoji kullan ama abartma (💜😔🌸✨ gibi, 1-2 mesajda bir)
  - Arkadaşınla konuşur gibi rahat ama bilgilendirici ol

  KARAKTER & TARZ:
  - Sıcak, samimi, yargılamayan ve güçlendirici bir arkadaş gibisin
  - Net, uygulanabilir öneriler verirsin; gereksiz uzatma yapmazsın
  - Kullanıcının mahremiyetine saygılısın ve empati kurar gibi dinlersin

  KURALLAR:
  - Tıbbi tanı koymaz, ciddi durumlarda uzmana yönlendirirsin
  - Kendine zarar, şiddet, nefret, yasa dışı konulara girmezsin
  - Bilmediğin bir şeyi uydurmaz, dürüstçe "bu konuda uzman değilim" dersin
  - OpenAI, GPT, ChatGPT gibi teknik terimleri KULLANMA

  🛍️ ÜRÜN KATALOĞUMUz (SADECE BU ÜRÜNLER VAR):

  1. **Cream Cleanser** - Kuru/hassas cilt için nazik temizleyici
  2. **Soothing Toner** - Kızarıklık ve hassasiyeti yatıştırır  
  3. **Serum Step-1** - Gözenek ve ton eşitsizliği için hazırlık
  4. **Serum Step-2** - Leke ve hiperpigmentasyon düzeltici
  5. **Serum Step-3** - Anti-aging, kırışıklık ve elastikiyet
  6. **Peptide Mask** - Özel günler için yoğun nem maskesi
  7. **3-Steps Set** - Komple rutin seti (1+2+3 bir arada)

  ⚠️ ÇOK ÖNEMLİ ÜRÜN KURALLARI:
  ❌ ASLA başka marka önerme (La Roche-Posay, CeraVe, Neutrogena, Bioderma gibi)!
  ❌ ASLA "internetten araştır" veya "eczaneden al" deme!
  ✅ SADECE yukarıdaki 7 ürünü öner!
  ✅ Her cilt sorununda mutlaka ilgili ürünümüzü öner!
  ✅ Samimi ol: "bi bak derim", "çok beğeniyorum", "deneyebilirsin"
  ✅ En fazla 1-2 ürün öner (fazla bunaltma)

  ÜRÜN ÖNERİ TAKTİKLERİ:
  - "Cildim kuru" → Cream Cleanser öner
  - "Lekelerim var" → Serum Step-2 öner
  - "Kırışıklık başladı" → Serum Step-3 öner
  - "Gözeneklerim büyük" → Serum Step-1 öner
  - "Cildim hassas/kızarık" → Soothing Toner öner
  - "Özel gün/hızlı bakım" → Peptide Mask öner
  - "Rutin istiyorum" → 3-Steps Set öner

  ÖRNEK DOĞRU ÖNERİLER:

  Kullanıcı: "Cildim çok kuru ne yapmalıyım?"
  Sen: "Ayyy kuru cilt çok rahatsız edici ya 😔 Bol su iç ve nemlendiricini ihmal etme. Cream Cleanser'ımızı bi dene derim, cildi kurutmadan nazikçe temizliyor. Çok işine yarar bence!"

  Kullanıcı: "Yüzümde lekeler var"
  Sen: "Leke gerçekten sinir bozucu valla 😔 Güneş kremi şart! Serum Step-2'yi deneyebilirsin, leke için özel formülü var. Düzenli kullanınca fark ediyor."

  Kullanıcı: "Kırışıklıklarım başladı"
  Sen: "Ayy anlıyorum canım, yaş ilerledikçe herkeste oluyor 💜 Serum Step-3'ü çok beğeniyorum, cildi sıkılaştırmaya yardımcı oluyor. Bi bak istersen!"

  HAFIZA:
  - Kullanıcının önceki mesajlarını hatırla ve tekrar sorma
  - Daha önce önerdiğin ürünleri tekrarlama
  - Kişiselleştirilmiş önerilerde bulun

  ÖRNEK KONUŞMALAR (Bu tarzda konuş):

  Kullanıcı: "cildim çok kuru napmalıyım ya"
  Sen: "Ayyy anlıyorum canım, kış aylarında herkeste böyle oluyor 😔 Önce bol bol su içmeye dikkat et, sonra nemlendiriciyi ihmal etme. Cream Cleanser'ımız var mesela, cildi kurutmadan temizliyor, bi bak derim bence çok işine yarar!"

  Kullanıcı: "yüzümde lekeler var ne yapmalıyım"
  Sen: "Leke gerçekten sinir bozucu ya, anlıyorum 😔 Genelde güneş ya da hormonal sebepli oluyor. Şöyle yapalım: sabah-akşam düzenli C vitamini serumu kullan, güneş kremi şart (yoksa lekeler daha da koyulaşır valla). Serum Step-2'yi de deneyebilirsin, leke için özel formülü var, bi bak istersen!"

  Kullanıcı: "bugün çok yorgunum moralim bozuk"
  Sen: "Ayy canım benim 🫂 Bazen böyle günler olur, normal. Kendine biraz zaman ayır, belki rahatlatıcı bi maske yap, çay demle, müzik aç. Peptide Mask'ımız var mesela, hem cildin hem moralin düzelir bence, ama önce dinlen biraz 💜"

  Kullanıcı: "sen kimsin nasıl çalışıyorsun"
  Sen: "Ben Mert Group ekibi tarafından özellikle kadınların cilt bakımı ve genel sağlığı için geliştirilmiş yapay zeka asistanıyım 💜 Sorularına samimi tavsiyelerde bulunuyorum, ürün önerilerim var ama asla zorlama yapmam. Sen ne konuşmak istersin?"

  Kullanıcı: "hangi gpt modelini kullanıyorsun"
  Sen: "Mert Group'un kendi geliştirdiği yapay zeka teknolojisini kullanıyorum 😊 Teknik detayları pek bilmiyorum ama sana yardımcı olmak için buradayım! Cilt bakımı, rutin, ürün önerisi gibi konularda yardımcı olabilirim, ne dersin?"`,
        carePrompt: 'Bakım Modu: cilt/saç/vücut rutini, adım adım, uygulanabilir öneriler.',
        motivationPrompt: 'Motivasyon Modu: sıcak, güçlendirici, duygu odaklı destek; klinik tavsiye yok.',
        dietPrompt: 'Beslenme Modu: dengeli rutin/alışkanlık; yargılayıcı dil yok; tıbbi diyet yazma.',
        blacklist: ['intihar', 'intihar et', 'öldür', 'bomb', 'bomba', 'yasadışı', 'tecavüz', 'zarar ver'],
      });
      await settings.save();
    }

    const { userId, message, pageUrl, mode } = req.body || {};
    const currentMode = mode || 'care';

    if (!message || message.trim().length === 0) {
      return res.status(400).json({ error: 'message gerekli' });
    }

    const MAX_MESSAGE_LENGTH = settings.maxMessageLength;
    if (message.length > MAX_MESSAGE_LENGTH) {
      return res.status(400).json({ error: `Mesajınız ${MAX_MESSAGE_LENGTH} karakterden uzun olamaz.` });
    }

    if (!userId || String(userId).trim().length === 0) {
      return res.status(400).json({ error: 'userId gerekli' });
    }

    // Dinamik blacklist kontrolü
    const blacklistCheck = (text, blacklist) => {
      if (!text) return false;
      const t = text.toLowerCase();
      return !blacklist.some((b) => t.includes(b.toLowerCase()));
    };

    if (!blacklistCheck(message, settings.blacklist)) {
      return res.json({
        reply:
          'Bu tür içeriklere burada detay veremem. Lütfen kendine zarar verici veya suç teşkil eden konulardan uzak dur ve gerekirse profesyonel destek al.',
      });
    }

    const systemPrompt = settings.systemPrompt;

    let modePrompt = '';
    switch (currentMode) {
      case 'care':
        modePrompt = settings.carePrompt;
        break;
      case 'motivation':
        modePrompt = settings.motivationPrompt;
        break;
      case 'diet':
        modePrompt = settings.dietPrompt;
        break;
      default:
        modePrompt = `Akıllı tavsiye modu: ihtiyaca göre denge kur.`;
    }

    // chatId varsa ona göre bul, yoksa userId'ye göre
    const { chatId } = req.body || {};
    let chat;
    if (chatId) {
      chat = await Chat.findById(chatId);
      if (!chat) {
        return res.status(404).json({ error: 'Sohbet bulunamadı' });
      }
    } else {
      chat = await Chat.findOne({ userId });
      if (!chat) chat = new Chat({ userId, messages: [] });
    }

    chat.messages.push({ role: 'user', content: message });
    await chat.save();

    const recentMessages = chat.messages.slice(-10).map((m) => ({ role: m.role, content: m.content }));

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'system', content: modePrompt },
      pageUrl ? { role: 'system', content: `Kullanıcı şu sayfada: ${pageUrl}.` } : null,
      ...recentMessages,
    ].filter(Boolean);

    const apiResponse = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: settings.model,
        messages,
        temperature: settings.temperature,
        max_tokens: settings.maxTokens || undefined,
        frequency_penalty: settings.frequencyPenalty || 0,
        presence_penalty: settings.presencePenalty || 0,
        top_p: settings.topP !== undefined ? settings.topP : 1,
      }),
    });

    if (!apiResponse.ok) {
      const errText = await apiResponse.text();
      console.error('OpenAI API hatası:', apiResponse.status, errText);
      return res.json({
        reply: 'Şu anda teknik bir sorun yaşıyorum, biraz sonra tekrar dener misin?',
      });
    }

    const data = await apiResponse.json();
    const reply = data.choices?.[0]?.message?.content?.trim() || 'Mesajını biraz daha detaylı yazar mısın?';

    // AI artık ürün önerilerini kendisi yapıyor (system prompt'ta talimat var)
    // Otomatik ürün ekleme kaldırıldı - daha doğal ve bağlam odaklı öneriler için

    chat.messages.push({ role: 'assistant', content: reply });
    await chat.save();

    return res.json({ reply });
  } catch (err) {
    console.error('Sunucu hatası:', err);
    return res.status(500).json({ error: 'Sunucu hatası', reply: 'Teknik sorun var, sonra tekrar dene.' });
  }
}

/* =========================================================
  7) Unified Chat API Handler (action-based)
  Frontend için tek endpoint üzerinden tüm işlemler
  ========================================================= */
async function handleUnifiedChatAPI(req, res) {
  const { action, userId, chatId, content, mode } = req.body;

  try {
    switch (action) {
      // Sohbet listesi
      case 'list': {
        if (!userId) return res.status(400).json({ error: 'userId gerekli' });

        const chats = await Chat.find({ userId, isArchived: false })
          .select('_id title mode isFavorite createdAt updatedAt messages')
          .sort({ updatedAt: -1 })
          .limit(50);

        const chatList = chats.map(chat => ({
          _id: chat._id,
          title: chat.title,
          mode: chat.mode,
          isFavorite: chat.isFavorite,
          messageCount: chat.messages.length,
          createdAt: chat.createdAt,
          updatedAt: chat.updatedAt,
        }));

        return res.json({ chats: chatList });
      }

      // Tek sohbet getir
      case 'get': {
        if (!chatId) return res.status(400).json({ error: 'chatId gerekli' });

        const chat = await Chat.findById(chatId);
        if (!chat) return res.status(404).json({ error: 'Sohbet bulunamadı' });

        return res.json({
          _id: chat._id,
          title: chat.title,
          messages: chat.messages,
          mode: chat.mode,
        });
      }

      // Yeni sohbet oluştur
      case 'new': {
        if (!userId) return res.status(400).json({ error: 'userId gerekli' });

        const chat = new Chat({
          userId,
          title: 'Yeni Sohbet',
          mode: mode || 'care',
          messages: [],
        });
        await chat.save();

        return res.json({ chatId: chat._id });
      }

      // Mesaj gönder
      case 'message': {
        if (!userId) return res.status(400).json({ error: 'userId gerekli' });
        if (!content || content.trim().length === 0) {
          return res.status(400).json({ error: 'content gerekli' });
        }
        if (!chatId) return res.status(400).json({ error: 'chatId gerekli' });

        // Chat'i bul
        const chat = await Chat.findById(chatId);
        if (!chat) return res.status(404).json({ error: 'Sohbet bulunamadı' });

        // Admin ayarlarını al
        let settings = await AdminSettings.findOne();
        if (!settings) {
          console.log('❌ AdminSettings bulunamadı, yeni oluşturuluyor...');
          settings = new AdminSettings({
            systemPrompt: 'Sen kadınlara yönelik özel bir yapay zeka asistanısın.',
            carePrompt: 'Bakım Modu: Samimi, uygulanabilir cilt bakımı önerileri.',
            motivationPrompt: 'Motivasyon Modu: Sıcak, güçlendirici destek ver.',
            dietPrompt: 'Beslenme Modu: Dengeli beslenme önerileri sun.',
            model: 'gpt-4o-mini',
            temperature: 0.7,
            blacklist: [],
          });
          await settings.save();
          console.log('✅ AdminSettings oluşturuldu');
        }

        console.log('📝 Settings:', {
          systemPrompt: settings.systemPrompt ? 'VAR ✅' : 'YOK ❌',
          carePrompt: settings.carePrompt ? 'VAR ✅' : 'YOK ❌',
          model: settings.model,
        });

        // Blacklist kontrolü
        const blacklistCheck = (text, blacklist) => {
          if (!text) return true;
          const t = text.toLowerCase();
          return !blacklist.some((b) => t.includes(b.toLowerCase()));
        };

        if (!blacklistCheck(content, settings.blacklist || [])) {
          return res.json({
            reply: 'Bu tür içeriklere burada detay veremem.',
            messages: chat.messages,
          });
        }

        // Kullanıcı mesajını ekle
        chat.messages.push({ role: 'user', content });

        // İlk mesajsa başlık oluştur
        if (chat.messages.filter(m => m.role === 'user').length === 1) {
          chat.title = content.substring(0, 40) + (content.length > 40 ? '...' : '');
        }

        // Mode prompt
        let modePrompt = '';
        const currentMode = mode || chat.mode || 'care';
        if (currentMode === 'care') modePrompt = settings.carePrompt || '';
        else if (currentMode === 'motivation') modePrompt = settings.motivationPrompt || '';
        else if (currentMode === 'diet') modePrompt = settings.dietPrompt || '';

        // Kullanıcı profil bilgilerini al (kişiselleştirme)
        let profilePrompt = '';
        try {
          const userIdRaw = userId.replace('google_', '');
          const userDoc = await User.findById(userIdRaw);
          if (userDoc && userDoc.profile && userDoc.profile.isProfileComplete) {
            const p = userDoc.profile;
            const parts = [];
            if (p.skinType) parts.push(`Cilt tipi: ${p.skinType}`);
            if (p.skinConcerns && p.skinConcerns.length > 0) parts.push(`Cilt sorunları: ${p.skinConcerns.join(', ')}`);
            if (p.age) parts.push(`Yaş aralığı: ${p.age}`);
            if (p.region) parts.push(`Bölge: ${p.region}`);
            if (p.allergies && p.allergies.length > 0) parts.push(`Alerjiler: ${p.allergies.join(', ')} - BU İÇERİKLERE DİKKAT ET, ÖNERİLERDE BUNLARDAN KAÇIN!`);
            if (p.sensitivities && p.sensitivities.length > 0) parts.push(`Hassasiyetler: ${p.sensitivities.join(', ')}`);
            if (parts.length > 0) {
              profilePrompt = `\n\n👤 KULLANICI PROFİLİ (önerileri buna göre kişiselleştir):\n${parts.join('\n')}`;
            }
          }
        } catch (profileErr) {
          console.log('Profil bilgisi alınamadı:', profileErr.message);
        }

        // Son 10 mesajı al
        const recentMessages = chat.messages.slice(-10).map((m) => ({ role: m.role, content: m.content }));

        const apiMessages = [
          { role: 'system', content: (settings.systemPrompt || 'Sen bir kadın yaşam asistanısın.') + profilePrompt },
          modePrompt ? { role: 'system', content: modePrompt } : null,
          ...recentMessages,
        ].filter(Boolean);

        console.log('🔍 API mesajları:', {
          systemPrompt: apiMessages[0]?.content?.substring(0, 50) + '...',
          modePrompt: apiMessages[1]?.content?.substring(0, 50) + '...',
          totalMessages: apiMessages.length,
        });

        // OpenAI API çağrısı
        const apiResponse = await fetch('https://api.openai.com/v1/chat/completions', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
          },
          body: JSON.stringify({
            model: settings.model || 'gpt-4o-mini',
            messages: apiMessages,
            temperature: settings.temperature || 0.6,
          }),
        });

        console.log('📡 OpenAI Response Status:', apiResponse.status);

        let reply = 'Şu anda teknik bir sorun yaşıyorum, biraz sonra tekrar dener misin?';
        if (apiResponse.ok) {
          const data = await apiResponse.json();
          reply = data.choices?.[0]?.message?.content?.trim() || reply;
          console.log('✅ API cevapı alındı:', reply.substring(0, 100) + '...');
        } else {
          const errText = await apiResponse.text();
          console.error('❌ API Hatası:', apiResponse.status, errText);
        }

        // AI cevabını ekle
        chat.messages.push({ role: 'assistant', content: reply });
        await chat.save();

        return res.json({
          reply,
          messages: chat.messages,
          chatId: chat._id,
          title: chat.title,
        });
      }

      // Tüm sohbetleri sil
      case 'deleteAll': {
        if (!userId) return res.status(400).json({ error: 'userId gerekli' });

        await Chat.deleteMany({ userId });
        return res.json({ success: true });
      }

      default:
        return res.status(400).json({ error: 'Geçersiz action' });
    }
  } catch (err) {
    console.error('Unified API error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
}

/* =========================================================
  8) Routes
  ========================================================= */

// Unified API endpoint (Frontend için)
app.post('/api/chat', chatLimiter, handleUnifiedChatAPI);

// Shopify App Proxy route (Sadece Shopify'dan signature ile gelen istekler)
app.post('/proxy/api/chat', verifyShopifyAppProxy, chatLimiter, handleChat);

/* =========================================================
  8.1) Google OAuth API
  ========================================================= */

// OAuth callback sayfası - popup'tan code alır ve ana sayfaya yönlendirir
app.get('/auth/google/callback', async (req, res) => {
  const { code, error } = req.query;

  if (error) {
    return res.redirect('/?error=login_cancelled');
  }

  if (!code) {
    return res.status(400).send('Authorization code eksik');
  }

  try {
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

    console.log('🔑 OAuth config check:', {
      hasClientId: !!GOOGLE_CLIENT_ID,
      hasClientSecret: !!GOOGLE_CLIENT_SECRET,
      clientSecretLength: GOOGLE_CLIENT_SECRET ? GOOGLE_CLIENT_SECRET.length : 0,
      clientSecretPrefix: GOOGLE_CLIENT_SECRET ? GOOGLE_CLIENT_SECRET.substring(0, 10) : 'N/A'
    });

    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
      return res.redirect('/?error=oauth_not_configured');
    }

    // Redirect URI - proxy arkasında HTTPS kullan
    const protocol = req.get('x-forwarded-proto') || req.protocol;
    const host = req.get('host');
    const redirectUri = `https://${host}/auth/google/callback`;

    console.log('🔗 OAuth redirect_uri:', redirectUri);

    // Code'u token'a çevir
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: redirectUri,
        grant_type: 'authorization_code',
      }),
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      console.error('Google token error:', tokenData);
      return res.redirect('/?error=token_failed&reason=' + encodeURIComponent(tokenData.error_description || tokenData.error));
    }

    // ID token'dan kullanıcı bilgilerini al
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const userInfo = await userInfoResponse.json();
    const { id: googleId, email, name, picture } = userInfo;

    // Kullanıcıyı bul veya oluştur
    let user = await User.findOne({ googleId });

    if (user) {
      user.lastLogin = new Date();
      user.name = name;
      user.picture = picture;
      await user.save();
    } else {
      user = new User({
        googleId,
        email,
        name,
        picture,
      });
      await user.save();
      console.log(`✅ Yeni kullanıcı kaydedildi: ${email}`);
    }

    // Kullanıcı bilgilerini URL-safe base64 olarak encode et
    const userData = Buffer.from(JSON.stringify({
      id: user._id,
      googleId: user.googleId,
      email: user.email,
      name: user.name,
      picture: user.picture,
    })).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

    // Ana sayfaya redirect et, kullanıcı bilgisi URL'de
    res.redirect(`/?auth_success=${userData}`);

  } catch (err) {
    console.error('Google callback error:', err);
    res.redirect('/?error=auth_failed');
  }
});

// OAuth code'u token'a çevir
app.post('/api/auth/google/code', async (req, res) => {
  try {
    const { code } = req.body;

    if (!code) {
      return res.status(400).json({ error: 'Authorization code gerekli' });
    }

    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;

    if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET) {
      return res.status(500).json({ error: 'Google OAuth yapılandırılmamış' });
    }

    // Code'u token'a çevir
    const tokenResponse = await fetch('https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        code,
        client_id: GOOGLE_CLIENT_ID,
        client_secret: GOOGLE_CLIENT_SECRET,
        redirect_uri: `${req.protocol}://${req.get('host')}/auth/google/callback`,
        grant_type: 'authorization_code',
      }),
    });

    const tokenData = await tokenResponse.json();

    if (tokenData.error) {
      console.error('Google token error:', tokenData);
      return res.status(401).json({ error: 'Token alınamadı: ' + tokenData.error_description });
    }

    // ID token'dan kullanıcı bilgilerini al
    const userInfoResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
      headers: { Authorization: `Bearer ${tokenData.access_token}` },
    });

    const userInfo = await userInfoResponse.json();
    const { id: googleId, email, name, picture } = userInfo;

    // Kullanıcıyı bul veya oluştur
    let user = await User.findOne({ googleId });

    if (user) {
      user.lastLogin = new Date();
      user.name = name;
      user.picture = picture;
      await user.save();
    } else {
      user = new User({
        googleId,
        email,
        name,
        picture,
      });
      await user.save();
      console.log(`✅ Yeni kullanıcı kaydedildi: ${email}`);
    }

    return res.json({
      success: true,
      user: {
        id: user._id,
        googleId: user.googleId,
        email: user.email,
        name: user.name,
        picture: user.picture,
      },
    });

  } catch (err) {
    console.error('Google code auth error:', err);
    return res.status(500).json({ error: 'Google ile giriş başarısız' });
  }
});

// Google ile giriş yap / kayıt ol (One Tap için - eski yöntem)
app.post('/api/auth/google', async (req, res) => {
  try {
    const { credential } = req.body;

    if (!credential) {
      return res.status(400).json({ error: 'Google credential gerekli' });
    }

    // Google ID token'ı doğrula
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    if (!GOOGLE_CLIENT_ID) {
      console.error('❌ GOOGLE_CLIENT_ID tanımlı değil!');
      return res.status(500).json({ error: 'Google OAuth yapılandırılmamış' });
    }

    // Token'ı Google'dan doğrula
    const googleResponse = await fetch(
      `https://oauth2.googleapis.com/tokeninfo?id_token=${credential}`
    );

    if (!googleResponse.ok) {
      return res.status(401).json({ error: 'Geçersiz Google token' });
    }

    const payload = await googleResponse.json();

    // Token'ın bizim app için olduğunu doğrula
    if (payload.aud !== GOOGLE_CLIENT_ID) {
      return res.status(401).json({ error: 'Token bu uygulama için değil' });
    }

    const { sub: googleId, email, name, picture } = payload;

    // Kullanıcıyı bul veya oluştur
    let user = await User.findOne({ googleId });

    if (user) {
      // Mevcut kullanıcı - son giriş güncelle
      user.lastLogin = new Date();
      user.name = name;
      user.picture = picture;
      await user.save();
    } else {
      // Yeni kullanıcı
      user = new User({
        googleId,
        email,
        name,
        picture,
      });
      await user.save();
      console.log(`✅ Yeni kullanıcı kaydedildi: ${email}`);
    }

    // Kullanıcı bilgilerini döndür
    return res.json({
      success: true,
      user: {
        id: user._id,
        googleId: user.googleId,
        email: user.email,
        name: user.name,
        picture: user.picture,
      },
    });

  } catch (err) {
    console.error('Google auth error:', err);
    return res.status(500).json({ error: 'Google ile giriş başarısız' });
  }
});

// Eski visitor sohbetlerini Google hesabına taşı
app.post('/api/auth/migrate-chats', async (req, res) => {
  try {
    const { visitorId, googleUserId } = req.body;

    if (!visitorId || !googleUserId) {
      return res.status(400).json({ error: 'visitorId ve googleUserId gerekli' });
    }

    // Eski visitor sohbetlerini bul ve güncelle
    const result = await Chat.updateMany(
      { userId: visitorId },
      { $set: { userId: `google_${googleUserId}` } }
    );

    // User'a eski visitorId'yi kaydet (referans için)
    await User.findByIdAndUpdate(googleUserId, { visitorId });

    console.log(`✅ ${result.modifiedCount} sohbet taşındı: ${visitorId} -> google_${googleUserId}`);

    return res.json({
      success: true,
      migratedCount: result.modifiedCount,
    });

  } catch (err) {
    console.error('Chat migration error:', err);
    return res.status(500).json({ error: 'Sohbetler taşınamadı' });
  }
});

// Kullanıcı bilgilerini getir
app.get('/api/auth/user/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    return res.json({
      id: user._id,
      email: user.email,
      name: user.name,
      picture: user.picture,
      createdAt: user.createdAt,
      lastLogin: user.lastLogin,
      profile: user.profile || {},
    });

  } catch (err) {
    console.error('Get user error:', err);
    return res.status(500).json({ error: 'Kullanıcı bilgileri alınamadı' });
  }
});

/* =========================================================
  8.2) KULLANICI PROFİL ANKETİ API
  ========================================================= */

// Profil bilgilerini kaydet/güncelle
app.put('/api/user/profile', async (req, res) => {
  try {
    const { userId, profile } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'userId gerekli' });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    // Profil alanlarını güncelle
    user.profile = {
      skinType: profile.skinType || '',
      skinConcerns: profile.skinConcerns || [],
      age: profile.age || '',
      gender: profile.gender || '',
      region: profile.region || '',
      allergies: profile.allergies || [],
      sensitivities: profile.sensitivities || [],
      isProfileComplete: true,
      completedAt: new Date(),
    };

    await user.save();
    console.log(`✅ Profil güncellendi: ${user.email}`);

    return res.json({ success: true, profile: user.profile });
  } catch (err) {
    console.error('Profile update error:', err);
    return res.status(500).json({ error: 'Profil güncellenemedi' });
  }
});

// Profil bilgilerini getir
app.get('/api/user/profile/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ error: 'Kullanıcı bulunamadı' });
    }

    return res.json({
      profile: user.profile || {},
      isComplete: user.profile?.isProfileComplete || false,
    });
  } catch (err) {
    console.error('Get profile error:', err);
    return res.status(500).json({ error: 'Profil bilgileri alınamadı' });
  }
});

// Frontend için config (Google Client ID, Firebase vb.)
app.get('/api/config', (req, res) => {
  res.json({
    googleClientId: process.env.GOOGLE_CLIENT_ID || null,
    firebase: {
      apiKey: process.env.FIREBASE_API_KEY || null,
      authDomain: process.env.FIREBASE_AUTH_DOMAIN || null,
      projectId: process.env.FIREBASE_PROJECT_ID || null,
      storageBucket: process.env.FIREBASE_STORAGE_BUCKET || null,
      messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID || null,
      appId: process.env.FIREBASE_APP_ID || null,
    },
    vapidKey: process.env.FIREBASE_VAPID_KEY || null,
  });
});

/* =========================================================
  8.1) PUSH NOTIFICATION API
  ========================================================= */

// Push subscription kaydet
app.post('/api/push/subscribe', async (req, res) => {
  try {
    const { userId, fcmToken, preferences, reminderTimes, timezone } = req.body;

    if (!userId || !fcmToken) {
      return res.status(400).json({ error: 'userId ve fcmToken gerekli' });
    }

    // Mevcut subscription'ı güncelle veya yeni oluştur
    const subscription = await PushSubscription.findOneAndUpdate(
      { fcmToken },
      {
        userId,
        fcmToken,
        device: req.body.device || 'web', // Mobil cihaz türünü (android/ios) kaydet
        userAgent: req.headers['user-agent'],
        preferences: preferences || {},
        reminderTimes: reminderTimes || {},
        timezone: timezone || 'Europe/Istanbul',
        isActive: true,
      },
      { upsert: true, new: true }
    );

    console.log(`✅ Push subscription kaydedildi: ${userId}`);
    res.json({ success: true, subscriptionId: subscription._id });
  } catch (err) {
    console.error('Push subscribe error:', err);
    res.status(500).json({ error: 'Subscription kaydedilemedi' });
  }
});

// Push subscription sil (bildirim kapatma)
app.post('/api/push/unsubscribe', async (req, res) => {
  try {
    const { fcmToken } = req.body;

    if (!fcmToken) {
      return res.status(400).json({ error: 'fcmToken gerekli' });
    }

    await PushSubscription.findOneAndUpdate(
      { fcmToken },
      { isActive: false }
    );

    console.log('✅ Push subscription devre dışı bırakıldı');
    res.json({ success: true });
  } catch (err) {
    console.error('Push unsubscribe error:', err);
    res.status(500).json({ error: 'İşlem başarısız' });
  }
});

// Kullanıcının bildirim tercihlerini güncelle (fcmToken ile)
app.put('/api/push/preferences', async (req, res) => {
  try {
    const { fcmToken, preferences, reminderTimes } = req.body;

    if (!fcmToken) {
      return res.status(400).json({ error: 'fcmToken gerekli' });
    }

    const update = {};
    if (preferences) update.preferences = preferences;
    if (reminderTimes) update.reminderTimes = reminderTimes;

    await PushSubscription.updateOne({ fcmToken, isActive: true }, update);

    res.json({ success: true });
  } catch (err) {
    console.error('Push preferences error:', err);
    res.status(500).json({ error: 'Tercihler güncellenemedi' });
  }
});

// Kullanıcının bildirim tercihlerini getir (fcmToken ile)
app.get('/api/push/preferences', async (req, res) => {
  try {
    const { fcmToken } = req.query;

    if (!fcmToken) {
      return res.status(400).json({ error: 'fcmToken gerekli' });
    }

    const subscription = await PushSubscription.findOne({ fcmToken, isActive: true });

    if (!subscription) {
      return res.json({
        enabled: false,
        preferences: {
          skincare: true,
          water: true,
          motivation: true,
          news: true,
        },
        reminderTimes: {
          morning: '08:00',
          evening: '21:00',
          waterInterval: 2,
        }
      });
    }

    res.json({
      enabled: true,
      preferences: subscription.preferences,
      reminderTimes: subscription.reminderTimes,
    });
  } catch (err) {
    console.error('Get preferences error:', err);
    res.status(500).json({ error: 'Tercihler alınamadı' });
  }
});

// Kullanıcının bildirim tercihlerini getir (userId ile - legacy)
app.get('/api/push/preferences/:userId', async (req, res) => {
  try {
    const { userId } = req.params;

    const subscription = await PushSubscription.findOne({ userId, isActive: true });

    if (!subscription) {
      return res.json({
        enabled: false,
        preferences: {
          skincare: true,
          water: true,
          motivation: true,
          news: true,
        },
        reminderTimes: {
          morning: '08:00',
          evening: '21:00',
          waterInterval: 2,
        }
      });
    }

    res.json({
      enabled: true,
      preferences: subscription.preferences,
      reminderTimes: subscription.reminderTimes,
    });
  } catch (err) {
    console.error('Get preferences error:', err);
    res.status(500).json({ error: 'Tercihler alınamadı' });
  }
});

// Push abone istatistikleri (Admin only)
app.get('/api/push/stats', adminAuthMiddleware, async (req, res) => {
  try {
    const subscriberCount = await PushSubscription.countDocuments({ isActive: true });
    const totalCount = await PushSubscription.countDocuments({});

    res.json({
      subscriberCount,
      totalCount,
    });
  } catch (err) {
    console.error('Push stats error:', err);
    res.status(500).json({ error: 'İstatistikler alınamadı' });
  }
});

// Test bildirimi gönder (Admin panel için)
app.post('/api/push/test', adminAuthMiddleware, async (req, res) => {
  try {
    const { title, body, url } = req.body;

    if (!title || !body) {
      return res.status(400).json({ error: 'title ve body gerekli' });
    }

    if (!firebaseInitialized) {
      return res.status(500).json({ error: 'Firebase yapılandırılmamış' });
    }

    // Aktif subscription'ları bul
    const subscriptions = await PushSubscription.find({ isActive: true }).limit(10);

    if (subscriptions.length === 0) {
      return res.status(400).json({ error: 'Aktif abone yok, önce bildirim iznini verin' });
    }

    let successCount = 0;
    let failedTokens = [];

    // Her subscription'a göndermeyi dene
    for (const sub of subscriptions) {
      try {
        const message = {
          token: sub.fcmToken,
          notification: {
            title,
            body,
          },
          webpush: {
            notification: {
              icon: '/favicon.svg',
              badge: '/favicon.svg',
            },
            fcmOptions: {
              link: url || '/',
            },
          },
          data: {
            type: 'test',
            url: url || '/',
            timestamp: String(Date.now()),
          },
        };

        const result = await admin.messaging().send(message);
        console.log('📬 Test bildirimi gönderildi:', result);
        successCount++;
        break; // Başarılı bir tane yeterli
      } catch (sendErr) {
        console.error('Token hatası:', sub.fcmToken.substring(0, 20) + '...', sendErr.code);

        // Geçersiz token'ları işaretle
        if (sendErr.code === 'messaging/registration-token-not-registered' ||
          sendErr.code === 'messaging/invalid-registration-token') {
          failedTokens.push(sub._id);
        }
      }
    }

    // Geçersiz token'ları deaktif et
    if (failedTokens.length > 0) {
      await PushSubscription.updateMany(
        { _id: { $in: failedTokens } },
        { isActive: false }
      );
      console.log(`🗑️ ${failedTokens.length} geçersiz token deaktif edildi`);
    }

    if (successCount > 0) {
      res.json({ success: true, message: 'Bildirim gönderildi', successCount });
    } else {
      res.status(400).json({
        error: 'Tüm token\'lar geçersiz. Lütfen ana sayfada tekrar bildirim izni verin.',
        invalidTokensRemoved: failedTokens.length
      });
    }
  } catch (err) {
    console.error('Push test error:', err);
    res.status(500).json({ error: 'Bildirim gönderilemedi', details: err.message });
  }
});

// Kullanıcı kendine test bildirimi gönder
app.post('/api/push/test-self', async (req, res) => {
  try {
    const { fcmToken, title, body } = req.body;

    if (!fcmToken) {
      return res.status(400).json({ error: 'fcmToken gerekli' });
    }

    if (!firebaseInitialized) {
      return res.status(500).json({ error: 'Firebase yapılandırılmamış' });
    }

    // Firebase Admin SDK ile bildirim gönder
    const message = {
      token: fcmToken,
      notification: {
        title: title || '💜 Women AI',
        body: body || 'Test bildirimi başarılı!',
      },
      webpush: {
        notification: {
          icon: '/favicon.svg',
          badge: '/favicon.svg',
        },
      },
      data: {
        type: 'test',
        timestamp: String(Date.now()),
      },
    };

    const result = await admin.messaging().send(message);
    console.log('📬 Test bildirimi gönderildi:', result);

    res.json({ success: true, message: 'Bildirim gönderildi', messageId: result });
  } catch (err) {
    console.error('Push test error:', err);
    res.status(500).json({ error: 'Bildirim gönderilemedi', details: err.message });
  }
});

// Toplu bildirim gönder (Admin only)
app.post('/api/push/broadcast', adminAuthMiddleware, async (req, res) => {
  try {
    const { title, body, url, type = 'news' } = req.body;

    if (!title || !body) {
      return res.status(400).json({ error: 'title ve body gerekli' });
    }

    if (!firebaseInitialized) {
      return res.status(500).json({ error: 'Firebase yapılandırılmamış' });
    }

    // Tüm aktif subscription'ları bul (preference filtresi kaldırıldı)
    const subscriptions = await PushSubscription.find({ isActive: true });

    console.log(`📊 Broadcast: ${subscriptions.length} aktif abone bulundu`);

    if (subscriptions.length === 0) {
      return res.json({ success: true, successCount: 0, failureCount: 0, message: 'Gönderilecek abone yok' });
    }

    // Tüm token'lara gönder (Firebase Admin SDK multicast)
    const tokens = subscriptions.map(s => s.fcmToken);

    const message = {
      notification: {
        title,
        body,
      },
      webpush: {
        notification: {
          icon: '/favicon.svg',
          badge: '/favicon.svg',
        },
        fcmOptions: {
          link: url || '/',
        },
      },
      data: { type, url: url || '/', timestamp: String(Date.now()) },
    };

    // Multicast gönder (max 500 token per batch)
    let successCount = 0;
    let failureCount = 0;

    for (let i = 0; i < tokens.length; i += 500) {
      const batch = tokens.slice(i, i + 500);
      const response = await admin.messaging().sendEachForMulticast({
        tokens: batch,
        ...message,
      });
      successCount += response.successCount;
      failureCount += response.failureCount;
    }

    console.log(`📬 Toplu bildirim: ${successCount}/${tokens.length} başarılı`);

    res.json({
      success: true,
      successCount,
      failureCount,
      total: tokens.length
    });
  } catch (err) {
    console.error('Broadcast error:', err);
    res.status(500).json({ error: 'Toplu bildirim gönderilemedi' });
  }
});

/* =========================================================
  9) SOHBET GEÇMİŞİ API - Chat History Routes (Legacy)
  ========================================================= */

// Kullanıcının tüm sohbetlerini listele
app.get('/api/chats/:userId', chatLimiter, async (req, res) => {
  try {
    const { userId } = req.params;
    const { archived, favorite, limit = 50 } = req.query;

    const query = { userId, isArchived: archived === 'true' };
    if (favorite === 'true') query.isFavorite = true;

    const chats = await Chat.find(query)
      .select('_id title mode isFavorite createdAt updatedAt messages')
      .sort({ updatedAt: -1 })
      .limit(parseInt(limit));

    // Sohbet listesi için özet bilgi döndür
    const chatList = chats.map(chat => ({
      id: chat._id,
      title: chat.title,
      mode: chat.mode,
      isFavorite: chat.isFavorite,
      messageCount: chat.messages.length,
      lastMessage: chat.messages.length > 0
        ? chat.messages[chat.messages.length - 1].content.substring(0, 60) + '...'
        : '',
      createdAt: chat.createdAt,
      updatedAt: chat.updatedAt,
    }));

    return res.json({ chats: chatList, total: chatList.length });
  } catch (err) {
    console.error('Chat list error:', err);
    return res.status(500).json({ error: 'Sohbetler yüklenemedi' });
  }
});

// Belirli bir sohbetin tüm mesajlarını getir
app.get('/api/chat/:chatId', chatLimiter, async (req, res) => {
  try {
    const { chatId } = req.params;

    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({ error: 'Sohbet bulunamadı' });
    }

    return res.json({
      id: chat._id,
      title: chat.title,
      mode: chat.mode,
      isFavorite: chat.isFavorite,
      isArchived: chat.isArchived,
      messages: chat.messages,
      createdAt: chat.createdAt,
      updatedAt: chat.updatedAt,
    });
  } catch (err) {
    console.error('Chat detail error:', err);
    return res.status(500).json({ error: 'Sohbet yüklenemedi' });
  }
});

// Yeni sohbet başlat
app.post('/api/chat/new', chatLimiter, async (req, res) => {
  try {
    const { userId, mode = 'care' } = req.body;

    if (!userId) {
      return res.status(400).json({ error: 'userId gerekli' });
    }

    const chat = new Chat({
      userId,
      mode,
      title: 'Yeni Sohbet',
      messages: [],
    });

    await chat.save();

    return res.json({
      id: chat._id,
      title: chat.title,
      mode: chat.mode,
      createdAt: chat.createdAt,
    });
  } catch (err) {
    console.error('New chat error:', err);
    return res.status(500).json({ error: 'Yeni sohbet oluşturulamadı' });
  }
});

// Sohbeti güncelle (başlık, favori, arşiv)
app.put('/api/chat/:chatId', chatLimiter, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { title, isFavorite, isArchived, mode } = req.body;

    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({ error: 'Sohbet bulunamadı' });
    }

    if (title !== undefined) chat.title = title;
    if (isFavorite !== undefined) chat.isFavorite = isFavorite;
    if (isArchived !== undefined) chat.isArchived = isArchived;
    if (mode !== undefined) chat.mode = mode;

    await chat.save();

    return res.json({
      ok: true, chat: {
        id: chat._id,
        title: chat.title,
        isFavorite: chat.isFavorite,
        isArchived: chat.isArchived,
        mode: chat.mode,
      }
    });
  } catch (err) {
    console.error('Update chat error:', err);
    return res.status(500).json({ error: 'Sohbet güncellenemedi' });
  }
});

// Sohbeti sil
app.delete('/api/chat/:chatId', chatLimiter, async (req, res) => {
  try {
    const { chatId } = req.params;

    const result = await Chat.findByIdAndDelete(chatId);
    if (!result) {
      return res.status(404).json({ error: 'Sohbet bulunamadı' });
    }

    return res.json({ ok: true, message: 'Sohbet silindi' });
  } catch (err) {
    console.error('Delete chat error:', err);
    return res.status(500).json({ error: 'Sohbet silinemedi' });
  }
});

// Belirli sohbete mesaj gönder (mevcut sohbete devam et)
app.post('/api/chat/:chatId/message', chatLimiter, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { message, pageUrl } = req.body;

    if (!message) {
      return res.status(400).json({ error: 'Mesaj gerekli' });
    }

    const chat = await Chat.findById(chatId);
    if (!chat) {
      return res.status(404).json({ error: 'Sohbet bulunamadı' });
    }

    // Mesajı ekle
    chat.messages.push({ role: 'user', content: message });

    // İlk mesajsa başlık oluştur
    if (chat.messages.filter(m => m.role === 'user').length === 1) {
      chat.generateTitle();
    }

    // Admin ayarlarını al
    let settings = await AdminSettings.findOne();
    if (!settings) settings = new AdminSettings();

    // System prompt
    const systemPrompt = settings.systemPrompt || 'Sen bir kadın yaşam ve bakım asistanısın.';

    // Mode prompt
    let modePrompt = '';
    if (chat.mode === 'care') modePrompt = settings.carePrompt || '';
    else if (chat.mode === 'motivation') modePrompt = settings.motivationPrompt || '';
    else if (chat.mode === 'diet') modePrompt = settings.dietPrompt || '';

    // Son 10 mesajı al
    const recentMessages = chat.messages.slice(-10).map((m) => ({ role: m.role, content: m.content }));

    const messages = [
      { role: 'system', content: systemPrompt },
      { role: 'system', content: modePrompt },
      pageUrl ? { role: 'system', content: `Kullanıcı şu sayfada: ${pageUrl}.` } : null,
      ...recentMessages,
    ].filter(Boolean);

    const apiResponse = await fetch('https://api.openai.com/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${process.env.OPENAI_API_KEY}`,
      },
      body: JSON.stringify({
        model: settings.model,
        messages,
        temperature: settings.temperature,
        max_tokens: settings.maxTokens || undefined,
        frequency_penalty: settings.frequencyPenalty || 0,
        presence_penalty: settings.presencePenalty || 0,
        top_p: settings.topP !== undefined ? settings.topP : 1,
      }),
    });

    if (!apiResponse.ok) {
      const errText = await apiResponse.text();
      console.error('OpenAI API hatası:', apiResponse.status, errText);
      return res.json({
        reply: 'Şu anda teknik bir sorun yaşıyorum, biraz sonra tekrar dener misin?',
      });
    }

    const data = await apiResponse.json();
    const reply = data.choices?.[0]?.message?.content?.trim() || 'Mesajını biraz daha detaylı yazar mısın?';

    chat.messages.push({ role: 'assistant', content: reply });
    await chat.save();

    return res.json({
      reply,
      chatId: chat._id,
      title: chat.title,
    });
  } catch (err) {
    console.error('Chat message error:', err);
    return res.status(500).json({ error: 'Mesaj gönderilemedi' });
  }
});

// Kullanıcının tüm sohbetlerini sil (hesap temizleme)
app.delete('/api/chats/:userId/all', chatLimiter, async (req, res) => {
  try {
    const { userId } = req.params;
    const { archived } = req.query;

    const query = { userId };
    if (archived === 'true') query.isArchived = true;

    const result = await Chat.deleteMany(query);

    return res.json({
      ok: true,
      deletedCount: result.deletedCount,
      message: `${result.deletedCount} sohbet silindi`
    });
  } catch (err) {
    console.error('Delete all chats error:', err);
    return res.status(500).json({ error: 'Sohbetler silinemedi' });
  }
});

/* =========================================================
  ADMIN ROUTES
  ========================================================= */

// Admin rate limiter (brute force koruması - Development'ta devre dışı)
const adminLimiter = IS_PRODUCTION ? rateLimit({
  windowMs: 15 * 60 * 1000, // 15 dakika
  max: 5, // 5 deneme
  message: { error: 'Çok fazla giriş denemesi. 15 dakika bekleyin.' },
}) : (req, res, next) => next(); // Development'ta bypass

// Admin login (Development modda Shopify doğrulaması yok)
app.post('/admin/login', adminLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Kullanıcı adı ve şifre gerekli' });
    }

    // Sadece username'e göre ara (shopDomain kontrolü kaldırıldı)
    const admin = await AdminUser.findOne({ username });
    if (!admin) {
      return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
    }

    // bcrypt ile şifre kontrolü
    const isPasswordValid = await admin.comparePassword(password);
    if (!isPasswordValid) {
      return res.status(401).json({ error: 'Geçersiz kullanıcı adı veya şifre' });
    }

    // 24 saat geçerli token
    const token = crypto.randomBytes(32).toString('hex');
    const expiry = new Date(Date.now() + 24 * 60 * 60 * 1000);

    admin.sessionToken = token;
    admin.tokenExpiry = expiry;
    await admin.save();

    console.log(`✅ Admin login: ${username} (${admin.shopDomain})`);
    return res.json({ token, expiresAt: expiry, shop: admin.shopDomain });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Admin logout
app.post('/admin/logout', adminAuthMiddleware, async (req, res) => {
  try {
    req.adminUser.sessionToken = null;
    req.adminUser.tokenExpiry = null;
    await req.adminUser.save();
    return res.json({ ok: true });
  } catch (err) {
    console.error('Logout error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Ayarları getir
app.get('/admin/settings', adminAuthMiddleware, async (req, res) => {
  try {
    let settings = await AdminSettings.findOne();
    if (!settings) {
      // İlk kez açılıyorsa default ayarları oluştur
      settings = new AdminSettings({
        systemPrompt: `Sen sadece kadınlara yönelik tasarlanmış özel bir bakım ve yaşam asistanısın.

  KİMLİK & TARZ:
  - Sıcak, samimi, yargılamayan ve güçlendirici bir arkadaş gibisin.
  - Net, uygulanabilir öneriler verirsin; gereksiz uzatma yapmazsın.
  - Kullanıcının mahremiyetine saygılısın ve empati kurar gibi dinlersin.

  KURALLAR:
  - Tıbbi tanı koymaz, ciddi durumlarda uzmana yönlendirirsin.
  - Kendine zarar, şiddet, nefret, yasa dışı konulara girmezsin.
  - Bilmediğin bir şeyi uydurmaz, dürüstçe "bu konuda uzman değilim" dersin.

  ÜRÜN ÖNERİ STRATEJİSİ:
  Mağazada şu ürünler var:
  1. Cream Cleanser - Günlük temizleyici (kuru/hassas cilt, nazik formül)
  2. Soothing Toner - Yatıştırıcı tonik (kızarıklık, hassasiyet, serum öncesi)
  3. Serum Step-1 - Hazırlık serumu (gözenek, ton eşitsizliği, mat cilt)
  4. Serum Step-2 - Düzeltici serum (leke, hiperpigmentasyon, kızarıklık)
  5. Serum Step-3 - Yoğun bakım serumu (anti-aging, kırışıklık, elastikiyet)
  6. Peptide Mask - Özel bakım maskesi (yoğun nem, ince çizgi, özel günler)
  7. 3-Steps Set - Komple rutin seti (hazırlama + düzeltme + güçlendirme)

  ÜRÜN ÖNERİ KURALLARI:
  ✅ NE ZAMAN ÖNER:
  - Kullanıcı cilt sorunu belirttiğinde ve ilgili ürün varsa
  - Rutin oluşturma konusunda yardım istediğinde
  - "Ne kullanmalıyım?" gibi doğrudan sorduğunda

  ❌ NE ZAMAN ÖNERMEZSİN:
  - Genel sohbette veya bilgi sorularında
  - Kullanıcı ürün istemiyorsa (sadece dinlemek istiyor)
  - Konuyla alakasız durumlarda
  - Her mesajında otomatik olarak

  📋 NASIL ÖNERİRSİN:
  - Doğal bir şekilde konuşma akışına entegre et
  - "Şu ürünü al" yerine "...için Step-2 Serum'u inceleyebilirsin" de
  - En fazla 1-2 ürün öner (kullanıcıyı bunaltma)
  - Ürün ismini ve ne işe yaradığını kısaca belirt
  - Zorlama yapma, seçenek sun: "istersen bakabilirsin"

  ÖRNEK DOĞRU KULLANIM:
  Kullanıcı: "Yüzümde lekeler var ne yapmalıyım?"
  Sen: "Leke için sabah-akşam C vitamini serumu + güneş kremi şart. Rutinine başlarken Serum Step-2'yi deneyebilirsin, hiperpigmentasyon için formülize edilmiş. Ayrıca güneşten korunmayı ihmal etme!"

  ÖRNEK YANLIŞ KULLANIM:
  Kullanıcı: "Bugün çok yorgunum"
  Sen: ❌ "Anladım. Bu arada Step-3 Serum ve Peptide Mask'ı denemelisin!" (alakasız)

  HAFIZA:
  - Kullanıcının önceki mesajlarını hatırla ve tekrar sorma
  - Daha önce önerdiğin ürünleri tekrarlama
  - Kişiselleştirilmiş önerilerde bulun`,
        carePrompt: 'Bakım Modu: cilt/saç/vücut rutini, adım adım, uygulanabilir öneriler.',
        motivationPrompt: 'Motivasyon Modu: sıcak, güçlendirici, duygu odaklı destek; klinik tavsiye yok.',
        dietPrompt: 'Beslenme Modu: dengeli rutin/alışkanlık; yargılayıcı dil yok; tıbbi diyet yazma.',
        blacklist: ['intihar', 'intihar et', 'öldür', 'bomb', 'bomba', 'yasadışı', 'tecavüz', 'zarar ver'],
        temperature: 0.4,
        model: 'gpt-4o-mini',
        maxMessageLength: 1000,
      });
      await settings.save();
    }
    return res.json(settings);
  } catch (err) {
    console.error('Settings error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Ayarları güncelle
app.put('/admin/settings', adminAuthMiddleware, async (req, res) => {
  try {
    const updates = req.body;
    let settings = await AdminSettings.findOne();

    if (!settings) {
      settings = new AdminSettings();
    }

    // Güncelleme yap
    if (updates.systemPrompt !== undefined) settings.systemPrompt = updates.systemPrompt;
    if (updates.carePrompt !== undefined) settings.carePrompt = updates.carePrompt;
    if (updates.motivationPrompt !== undefined) settings.motivationPrompt = updates.motivationPrompt;
    if (updates.dietPrompt !== undefined) settings.dietPrompt = updates.dietPrompt;
    if (updates.temperature !== undefined) settings.temperature = updates.temperature;
    if (updates.model !== undefined) settings.model = updates.model;
    if (updates.maxMessageLength !== undefined) settings.maxMessageLength = updates.maxMessageLength;
    if (updates.blacklist !== undefined) settings.blacklist = updates.blacklist;
    if (updates.rateLimitWindow !== undefined) settings.rateLimitWindow = updates.rateLimitWindow;
    if (updates.rateLimitMax !== undefined) settings.rateLimitMax = updates.rateLimitMax;
    if (updates.maxTokens !== undefined) settings.maxTokens = updates.maxTokens;
    if (updates.frequencyPenalty !== undefined) settings.frequencyPenalty = updates.frequencyPenalty;
    if (updates.presencePenalty !== undefined) settings.presencePenalty = updates.presencePenalty;
    if (updates.topP !== undefined) settings.topP = updates.topP;

    settings.updatedAt = new Date();
    await settings.save();

    return res.json({ ok: true, settings });
  } catch (err) {
    console.error('Update settings error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Admin paneli sayfasını sun (Development modda güvenlik yok)
app.get('/admin', (req, res) => {
  res.sendFile(__dirname + '/admin-panel.html');
});

// Admin paneli için proxy route (Shopify App içinden)
app.get('/proxy/admin', verifyShopifyAppProxy, (req, res) => {
  res.sendFile(__dirname + '/admin-panel.html');
});

// İstatistikler
app.get('/admin/stats', adminAuthMiddleware, async (req, res) => {
  try {
    const totalChats = await Chat.countDocuments();
    const totalMessages = await Chat.aggregate([
      { $project: { messageCount: { $size: '$messages' } } },
      { $group: { _id: null, total: { $sum: '$messageCount' } } },
    ]);

    return res.json({
      totalChats,
      totalMessages: totalMessages[0]?.total || 0,
      uptime: process.uptime(),
    });
  } catch (err) {
    console.error('Stats error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
});

/* =========================================================
  KULLANICI DAVRANIŞ TAKİBİ API
  ========================================================= */

// Batch activity log endpoint
app.post('/api/activity', async (req, res) => {
  try {
    const { events, sessionId, userId, device } = req.body;

    if (!events || !Array.isArray(events) || events.length === 0) {
      return res.status(400).json({ error: 'events array gerekli' });
    }

    // Max 50 event per batch
    const batch = events.slice(0, 50).map(evt => ({
      userId: userId || 'anonymous',
      sessionId: sessionId || 'unknown',
      event: evt.event,
      category: evt.category || 'interaction',
      data: evt.data || {},
      page: evt.page || '',
      duration: evt.duration || 0,
      device: device || {},
      createdAt: evt.timestamp ? new Date(evt.timestamp) : new Date(),
    }));

    await ActivityLog.insertMany(batch, { ordered: false });

    return res.json({ ok: true, count: batch.length });
  } catch (err) {
    console.error('Activity log error:', err.message);
    return res.json({ ok: true }); // Client'ı bloklamayalım
  }
});

// Admin: Davranış istatistikleri
app.get('/admin/activity-stats', adminAuthMiddleware, async (req, res) => {
  try {
    const { days = 7 } = req.query;
    const since = new Date();
    since.setDate(since.getDate() - parseInt(days));

    // Toplam benzersiz kullanıcı
    const uniqueUsers = await ActivityLog.distinct('userId', {
      createdAt: { $gte: since },
    });

    // Toplam oturum
    const uniqueSessions = await ActivityLog.distinct('sessionId', {
      createdAt: { $gte: since },
    });

    // Event dağılımı
    const eventBreakdown = await ActivityLog.aggregate([
      { $match: { createdAt: { $gte: since } } },
      { $group: { _id: '$event', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 20 },
    ]);

    // Günlük aktif kullanıcı
    const dailyActive = await ActivityLog.aggregate([
      { $match: { createdAt: { $gte: since } } },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } },
            userId: '$userId',
          },
        },
      },
      {
        $group: {
          _id: '$_id.date',
          activeUsers: { $sum: 1 },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    // Sayfa görüntüleme dağılımı
    const pageViews = await ActivityLog.aggregate([
      { $match: { createdAt: { $gte: since }, event: 'page_view' } },
      { $group: { _id: '$page', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    // Ortalama oturum süresi
    const avgSession = await ActivityLog.aggregate([
      { $match: { createdAt: { $gte: since }, event: 'session_end' } },
      { $group: { _id: null, avgDuration: { $avg: '$duration' } } },
    ]);

    // Mod kullanım dağılımı
    const modeUsage = await ActivityLog.aggregate([
      { $match: { createdAt: { $gte: since }, event: 'mode_change' } },
      { $group: { _id: '$data.mode', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    // Saatlik aktivite yoğunluğu
    const hourlyActivity = await ActivityLog.aggregate([
      { $match: { createdAt: { $gte: since } } },
      { $group: { _id: { $hour: '$createdAt' }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]);

    // Cihaz dağılımı
    const deviceBreakdown = await ActivityLog.aggregate([
      { $match: { createdAt: { $gte: since } } },
      { $group: { _id: '$device.type', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    return res.json({
      period: `${days} gün`,
      totalUniqueUsers: uniqueUsers.length,
      totalSessions: uniqueSessions.length,
      avgSessionDuration: avgSession[0]?.avgDuration || 0,
      eventBreakdown,
      dailyActiveUsers: dailyActive,
      pageViews,
      modeUsage,
      hourlyActivity,
      deviceBreakdown,
    });
  } catch (err) {
    console.error('Activity stats error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
});

// Health
app.get('/health', (req, res) => res.json({ ok: true }));

/* =========================================================
  SOHBET İSTATİSTİKLERİ DASHBOARD API
  ========================================================= */
app.get('/admin/chat-stats', adminAuthMiddleware, async (req, res) => {
  try {
    const { days = 30 } = req.query;
    const since = new Date();
    since.setDate(since.getDate() - parseInt(days));

    // 1) Günlük mesaj sayısı
    const dailyMessages = await Chat.aggregate([
      { $unwind: '$messages' },
      { $match: { 'messages.timestamp': { $gte: since } } },
      {
        $group: {
          _id: { $dateToString: { format: '%Y-%m-%d', date: '$messages.timestamp' } },
          count: { $sum: 1 },
          userMsgs: { $sum: { $cond: [{ $eq: ['$messages.role', 'user'] }, 1, 0] } },
          aiMsgs: { $sum: { $cond: [{ $eq: ['$messages.role', 'assistant'] }, 1, 0] } },
        },
      },
      { $sort: { _id: 1 } },
    ]);

    // 2) Mod dağılımı
    const modeDistribution = await Chat.aggregate([
      { $match: { updatedAt: { $gte: since } } },
      { $group: { _id: '$mode', count: { $sum: 1 } } },
      { $sort: { count: -1 } },
    ]);

    // 3) Saatlik mesaj yoğunluğu
    const hourlyMessages = await Chat.aggregate([
      { $unwind: '$messages' },
      { $match: { 'messages.timestamp': { $gte: since } } },
      { $group: { _id: { $hour: '$messages.timestamp' }, count: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]);

    // 4) Ortalama mesaj/sohbet
    const avgMessagesPerChat = await Chat.aggregate([
      { $match: { updatedAt: { $gte: since } } },
      { $project: { msgCount: { $size: '$messages' } } },
      { $group: { _id: null, avg: { $avg: '$msgCount' }, max: { $max: '$msgCount' }, min: { $min: '$msgCount' } } },
    ]);

    // 5) Aktif kullanıcılar (son N günde mesaj atan)
    const activeUsers = await Chat.aggregate([
      { $match: { updatedAt: { $gte: since } } },
      { $group: { _id: '$userId' } },
      { $count: 'total' },
    ]);

    // 6) En aktif kullanıcılar (top 10)
    const topUsers = await Chat.aggregate([
      { $match: { updatedAt: { $gte: since } } },
      { $project: { userId: 1, msgCount: { $size: '$messages' } } },
      { $group: { _id: '$userId', totalMessages: { $sum: '$msgCount' }, chatCount: { $sum: 1 } } },
      { $sort: { totalMessages: -1 } },
      { $limit: 10 },
    ]);

    // Kullanıcı isimleri çek
    const userIds = topUsers.map(u => u._id.replace('google_', ''));
    const users = await User.find({ googleId: { $in: userIds } }, 'googleId name email');
    const userMap = {};
    users.forEach(u => { userMap[`google_${u.googleId}`] = u.name || u.email; });

    const topUsersWithNames = topUsers.map(u => ({
      userId: u._id,
      name: userMap[u._id] || u._id,
      totalMessages: u.totalMessages,
      chatCount: u.chatCount,
    }));

    // 7) Mesaj uzunluk dağılımı
    const messageLengths = await Chat.aggregate([
      { $unwind: '$messages' },
      { $match: { 'messages.timestamp': { $gte: since }, 'messages.role': 'user' } },
      {
        $bucket: {
          groupBy: { $strLenCP: '$messages.content' },
          boundaries: [0, 50, 100, 200, 500, 1000, 5000],
          default: '5000+',
          output: { count: { $sum: 1 } },
        },
      },
    ]);

    // 8) Haftalık karşılaştırma
    const lastWeek = new Date();
    lastWeek.setDate(lastWeek.getDate() - 7);
    const prevWeek = new Date();
    prevWeek.setDate(prevWeek.getDate() - 14);

    const thisWeekMsgs = await Chat.aggregate([
      { $unwind: '$messages' },
      { $match: { 'messages.timestamp': { $gte: lastWeek } } },
      { $count: 'total' },
    ]);

    const prevWeekMsgs = await Chat.aggregate([
      { $unwind: '$messages' },
      { $match: { 'messages.timestamp': { $gte: prevWeek, $lt: lastWeek } } },
      { $count: 'total' },
    ]);

    const thisWeekTotal = thisWeekMsgs[0]?.total || 0;
    const prevWeekTotal = prevWeekMsgs[0]?.total || 0;
    const weeklyGrowth = prevWeekTotal > 0 ? Math.round(((thisWeekTotal - prevWeekTotal) / prevWeekTotal) * 100) : 100;

    // 9) Kullanıcı profil tamamlama oranı
    const totalUsers = await User.countDocuments();
    const completedProfiles = await User.countDocuments({ 'profile.isProfileComplete': true });

    // 10) Günlük aktif kullanıcı (DAU)
    const dailyActiveUsers = await Chat.aggregate([
      { $match: { updatedAt: { $gte: since } } },
      {
        $group: {
          _id: {
            date: { $dateToString: { format: '%Y-%m-%d', date: '$updatedAt' } },
            userId: '$userId',
          },
        },
      },
      { $group: { _id: '$_id.date', activeUsers: { $sum: 1 } } },
      { $sort: { _id: 1 } },
    ]);

    return res.json({
      period: `${days} gün`,
      dailyMessages,
      modeDistribution,
      hourlyMessages,
      avgMessagesPerChat: {
        avg: Math.round((avgMessagesPerChat[0]?.avg || 0) * 10) / 10,
        max: avgMessagesPerChat[0]?.max || 0,
        min: avgMessagesPerChat[0]?.min || 0,
      },
      activeUsers: activeUsers[0]?.total || 0,
      topUsers: topUsersWithNames,
      messageLengths,
      weeklyComparison: {
        thisWeek: thisWeekTotal,
        prevWeek: prevWeekTotal,
        growth: weeklyGrowth,
      },
      profileCompletion: {
        total: totalUsers,
        completed: completedProfiles,
        rate: totalUsers > 0 ? Math.round((completedProfiles / totalUsers) * 100) : 0,
      },
      dailyActiveUsers,
    });
  } catch (err) {
    console.error('Chat stats error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
});

/* =========================================================
  POPÜLER SORULAR ANALİZİ API
  ========================================================= */

// Türkçe stop words (analiz dışı bırakılacak kelimeler)
const TURKISH_STOP_WORDS = new Set([
  'bir', 'bu', 'şu', 'o', 've', 'ile', 'de', 'da', 'mi', 'mı', 'mu', 'mü',
  'ne', 'nasıl', 'için', 'ben', 'sen', 'biz', 'siz', 'var', 'yok', 'çok',
  'daha', 'en', 'gibi', 'olan', 'olarak', 'bana', 'beni', 'benim', 'sana',
  'lütfen', 'evet', 'hayır', 'tamam', 'iyi', 'ama', 'fakat', 'veya', 'ya',
  'her', 'tüm', 'olan', 'olur', 'olabilir', 'lazım', 'gerek', 'kadar',
  'sonra', 'önce', 'arasında', 'üzerinde', 'altında', 'içinde', 'hakkında',
  'merhaba', 'selam', 'teşekkür', 'teşekkürler', 'sağol', 'ederim', 'ederiz',
  'biraz', 'bazı', 'böyle', 'şöyle', 'öyle', 'hangisi', 'hangi', 'neden',
  'nerede', 'nereden', 'nereye', 'neler', 'kim', 'kimin', 'kime',
  'güzel', 'bakar', 'misin', 'musun', 'söyler', 'yapar', 'eder',
  'the', 'is', 'a', 'an', 'and', 'or', 'to', 'in', 'on', 'at', 'for',
]);

// Konu kategorileri ve anahtar kelimeler
const TOPIC_CATEGORIES = {
  'Cilt Bakımı': ['cilt', 'bakım', 'rutin', 'temizleme', 'temizleyici', 'nemlendirici', 'serum', 'tonik', 'maske', 'peeling', 'gözenek', 'pürüz', 'gece', 'sabah'],
  'Güneş Koruması': ['güneş', 'spf', 'koruma', 'güneş kremi', 'uv', 'bronzlaşma', 'leke'],
  'Akne & Sivilce': ['akne', 'sivilce', 'siyah nokta', 'beyaz nokta', 'kızarıklık', 'iltihap', 'iz', 'yara'],
  'Yaşlanma Karşıtı': ['kırışıklık', 'yaşlanma', 'anti-aging', 'retinol', 'kolajen', 'sıkılaştırma', 'elastikiyet', 'botoks'],
  'Saç Bakımı': ['saç', 'şampuan', 'saç bakımı', 'dökülme', 'kepek', 'kırılma', 'saç maskesi'],
  'Beslenme & Diyet': ['beslenme', 'diyet', 'yemek', 'kalori', 'protein', 'vitamin', 'mineral', 'su', 'besin', 'gıda', 'tarif', 'yiyecek'],
  'Makyaj': ['makyaj', 'fondöten', 'ruj', 'far', 'maskara', 'kapatıcı', 'allık', 'pudra', 'eyeliner'],
  'Vücut Bakımı': ['vücut', 'selülit', 'çatlak', 'bacak', 'kol', 'el', 'ayak', 'tırnak'],
  'Hassas Cilt': ['hassas', 'hassasiyet', 'tahriş', 'alerji', 'alerjik', 'kızarma', 'yanma', 'batma'],
  'Motivasyon': ['motivasyon', 'özgüven', 'mutlu', 'güzel', 'kendimi', 'moral', 'destek', 'stres'],
};

// Popüler sorular endpoint
app.get('/admin/popular-questions', adminAuthMiddleware, async (req, res) => {
  try {
    const { days = 30, limit = 50 } = req.query;
    const since = new Date();
    since.setDate(since.getDate() - parseInt(days));

    // Tüm kullanıcı mesajlarını çek
    const chats = await Chat.aggregate([
      { $unwind: '$messages' },
      { $match: {
        'messages.role': 'user',
        'messages.timestamp': { $gte: since },
      }},
      { $project: {
        content: '$messages.content',
        timestamp: '$messages.timestamp',
        mode: 1,
        userId: 1,
      }},
      { $sort: { timestamp: -1 } },
      { $limit: parseInt(limit) * 20 }, // Analiz için fazla çek
    ]);

    if (chats.length === 0) {
      return res.json({
        totalQuestions: 0,
        topQuestions: [],
        categories: [],
        wordFrequency: [],
        questionsByMode: [],
        dailyQuestionTrend: [],
        avgQuestionLength: 0,
      });
    }

    // 1) Mesajları temizle ve normalize et
    const allMessages = chats.map(c => ({
      content: c.content.trim().toLowerCase(),
      original: c.content.trim(),
      mode: c.mode,
      timestamp: c.timestamp,
      userId: c.userId,
    }));

    // 2) Benzer soruları grupla (basit benzerlik - ilk 40 karakter)
    const questionGroups = {};
    allMessages.forEach(msg => {
      if (msg.content.length < 5) return; // Çok kısa mesajları atla
      const key = msg.content.substring(0, 40).replace(/[?!.,;:]/g, '').trim();
      if (!questionGroups[key]) {
        questionGroups[key] = {
          sample: msg.original,
          count: 0,
          modes: {},
          users: new Set(),
        };
      }
      questionGroups[key].count++;
      questionGroups[key].modes[msg.mode] = (questionGroups[key].modes[msg.mode] || 0) + 1;
      questionGroups[key].users.add(msg.userId);
    });

    // Top sorular
    const topQuestions = Object.values(questionGroups)
      .map(g => ({
        question: g.sample.length > 80 ? g.sample.substring(0, 80) + '...' : g.sample,
        count: g.count,
        uniqueUsers: g.users.size,
        modes: g.modes,
      }))
      .sort((a, b) => b.count - a.count)
      .slice(0, parseInt(limit));

    // 3) Kelime frekansı analizi
    const wordCounts = {};
    allMessages.forEach(msg => {
      const words = msg.content
        .replace(/[?!.,;:'"()\[\]{}]/g, ' ')
        .split(/\s+/)
        .filter(w => w.length > 2 && !TURKISH_STOP_WORDS.has(w));
      
      words.forEach(word => {
        wordCounts[word] = (wordCounts[word] || 0) + 1;
      });
    });

    const wordFrequency = Object.entries(wordCounts)
      .map(([word, count]) => ({ word, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 40);

    // 4) Kategori analizi
    const categoryCounts = {};
    allMessages.forEach(msg => {
      for (const [category, keywords] of Object.entries(TOPIC_CATEGORIES)) {
        const found = keywords.some(kw => msg.content.includes(kw));
        if (found) {
          categoryCounts[category] = (categoryCounts[category] || 0) + 1;
        }
      }
    });

    const categories = Object.entries(categoryCounts)
      .map(([name, count]) => ({
        name,
        count,
        percentage: Math.round((count / allMessages.length) * 100),
      }))
      .sort((a, b) => b.count - a.count);

    // 5) Mode bazlı soru dağılımı
    const modeQuestions = {};
    allMessages.forEach(msg => {
      modeQuestions[msg.mode] = (modeQuestions[msg.mode] || 0) + 1;
    });
    const questionsByMode = Object.entries(modeQuestions)
      .map(([mode, count]) => ({ mode, count }))
      .sort((a, b) => b.count - a.count);

    // 6) Günlük soru trendi
    const dailyCounts = {};
    allMessages.forEach(msg => {
      const day = msg.timestamp.toISOString().split('T')[0];
      dailyCounts[day] = (dailyCounts[day] || 0) + 1;
    });
    const dailyQuestionTrend = Object.entries(dailyCounts)
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date));

    // 7) Ortalama soru uzunluğu
    const avgLen = Math.round(allMessages.reduce((s, m) => s + m.content.length, 0) / allMessages.length);

    return res.json({
      totalQuestions: allMessages.length,
      topQuestions,
      categories,
      wordFrequency,
      questionsByMode,
      dailyQuestionTrend,
      avgQuestionLength: avgLen,
    });
  } catch (err) {
    console.error('Popular questions error:', err);
    return res.status(500).json({ error: 'Sunucu hatası' });
  }
});

/* =========================================================
  HATIRLATICI SİSTEMİ (Scheduler)
  ========================================================= */

// Hatırlatıcı mesajları
const REMINDER_MESSAGES = {
  skincare: {
    morning: [
      { title: '☀️ Günaydın!', body: 'Sabah bakım rutinine başla! Temizle, tonla, nemlendir 💜' },
      { title: '🌸 Güne güzel başla!', body: 'Cildine sabah bakımını yaptın mı?' },
      { title: '✨ Işıltılı bir güne!', body: 'Güneş kremi sürmeni unutma! SPF şart ☀️' },
    ],
    evening: [
      { title: '🌙 İyi akşamlar!', body: 'Makyajını temizle, gece serumunu uygula 💜' },
      { title: '😴 Uyumadan önce...', body: 'Gece bakım rutinini unutma! Cildin sana teşekkür edecek' },
      { title: '🧴 Gece bakımı zamanı!', body: 'Temizle + serum + nemlendirici. Güzellik uykusu başlasın!' },
    ],
  },
  water: [
    { title: '💧 Su molası!', body: 'Bir bardak su iç, cildin parlasın!' },
    { title: '🚰 Hatırlatma!', body: 'Su içmeyi unutma! Günde 8 bardak hedefi 💪' },
    { title: '💦 Hidrasyon zamanı!', body: 'Vücudun suya ihtiyaç duyuyor, iç biraz!' },
    { title: '🥤 Su iç!', body: 'Güzel cilt = bol su. Hadi bir bardak!' },
  ],
};

// Rastgele mesaj seç
function getRandomMessage(messages) {
  return messages[Math.floor(Math.random() * messages.length)];
}

// Belirli saatte bildirim gönder
async function sendScheduledNotifications(type, timeField) {
  if (!firebaseInitialized) {
    console.log('⚠️ Firebase hazır değil, bildirim gönderilemedi');
    return;
  }

  try {
    const now = new Date();
    const currentHour = now.getHours().toString().padStart(2, '0');
    const currentMinute = now.getMinutes().toString().padStart(2, '0');
    const currentTime = `${currentHour}:${currentMinute}`;

    // Bu saatte bildirim alması gereken kullanıcıları bul
    const query = {
      isActive: true,
      [`preferences.${type}`]: true,
    };

    if (timeField) {
      // Tam saat eşleşmesi (örn: 08:00)
      query[`reminderTimes.${timeField}`] = currentTime;
    }

    const subscriptions = await PushSubscription.find(query);

    if (subscriptions.length === 0) {
      return;
    }

    console.log(`⏰ ${type} hatırlatıcı: ${subscriptions.length} kullanıcıya gönderiliyor (${currentTime})`);

    // Mesaj seç
    let message;
    if (type === 'skincare') {
      const period = timeField === 'morning' ? 'morning' : 'evening';
      message = getRandomMessage(REMINDER_MESSAGES.skincare[period]);
    } else if (type === 'water') {
      message = getRandomMessage(REMINDER_MESSAGES.water);
    }

    if (!message) return;

    // Her kullanıcıya gönder
    const tokens = subscriptions.map(s => s.fcmToken);

    for (let i = 0; i < tokens.length; i += 500) {
      const batch = tokens.slice(i, i + 500);
      try {
        const response = await admin.messaging().sendEachForMulticast({
          tokens: batch,
          notification: {
            title: message.title,
            body: message.body,
          },
          webpush: {
            notification: {
              icon: '/favicon.svg',
              badge: '/favicon.svg',
            },
            fcmOptions: {
              link: '/',
            },
          },
          data: {
            type: 'reminder',
            reminderType: type,
          },
        });
        console.log(`📬 ${type} hatırlatıcı: ${response.successCount}/${batch.length} başarılı`);
      } catch (err) {
        console.error(`❌ ${type} hatırlatıcı gönderim hatası:`, err.message);
      }
    }

    // Son bildirim zamanını güncelle
    await PushSubscription.updateMany(
      { fcmToken: { $in: tokens } },
      { lastNotification: new Date() }
    );

  } catch (err) {
    console.error(`❌ ${type} scheduler hatası:`, err);
  }
}

// Su hatırlatıcısı (her 2 saatte)
async function sendWaterReminders() {
  if (!firebaseInitialized) return;

  try {
    const now = new Date();
    const currentHour = now.getHours();

    // Sadece gündüz saatlerinde (07:00 - 22:00)
    if (currentHour < 7 || currentHour > 22) {
      return;
    }

    // Su hatırlatıcısı açık olan kullanıcıları bul
    const subscriptions = await PushSubscription.find({
      isActive: true,
      'preferences.water': true,
    });

    if (subscriptions.length === 0) return;

    // Her kullanıcının interval'ına göre filtrele
    const eligibleSubscriptions = subscriptions.filter(sub => {
      const interval = sub.reminderTimes?.waterInterval || 2;
      // Son bildirimden bu yana yeterli süre geçti mi?
      if (sub.lastNotification) {
        const hoursSinceLastNotification = (now - sub.lastNotification) / (1000 * 60 * 60);
        return hoursSinceLastNotification >= interval;
      }
      return true; // Hiç bildirim almamışsa gönder
    });

    if (eligibleSubscriptions.length === 0) return;

    console.log(`💧 Su hatırlatıcı: ${eligibleSubscriptions.length} kullanıcıya gönderiliyor`);

    const message = getRandomMessage(REMINDER_MESSAGES.water);
    const tokens = eligibleSubscriptions.map(s => s.fcmToken);

    for (let i = 0; i < tokens.length; i += 500) {
      const batch = tokens.slice(i, i + 500);
      try {
        const response = await admin.messaging().sendEachForMulticast({
          tokens: batch,
          notification: {
            title: message.title,
            body: message.body,
          },
          webpush: {
            notification: {
              icon: '/favicon.svg',
              badge: '/favicon.svg',
            },
          },
          data: {
            type: 'reminder',
            reminderType: 'water',
          },
        });
        console.log(`💧 Su hatırlatıcı: ${response.successCount}/${batch.length} başarılı`);
      } catch (err) {
        console.error('❌ Su hatırlatıcı hatası:', err.message);
      }
    }

    // Son bildirim zamanını güncelle
    await PushSubscription.updateMany(
      { fcmToken: { $in: tokens } },
      { lastNotification: new Date() }
    );

  } catch (err) {
    console.error('❌ Su scheduler hatası:', err);
  }
}

// Cron Jobs başlat
function startReminderScheduler() {
  if (!cron) {
    console.log('⚠️ node-cron mevcut değil, scheduler başlatılmadı');
    return;
  }

  console.log('⏰ Hatırlatıcı scheduler başlatılıyor...');

  // Her dakika çalış - kullanıcının ayarladığı saatleri kontrol et
  // Cilt bakımı sabah hatırlatıcısı (her dakika kontrol, eşleşen saatte gönder)
  cron.schedule('* * * * *', () => {
    sendScheduledNotifications('skincare', 'morning');
    sendScheduledNotifications('skincare', 'evening');
  });

  // Su hatırlatıcısı - her saat başı (07:00 - 22:00 arası)
  cron.schedule('0 7-22 * * *', () => {
    sendWaterReminders();
  });

  console.log('✅ Hatırlatıcı scheduler aktif');
  console.log('   📅 Cilt bakımı: Kullanıcının ayarladığı saatlerde');
  console.log('   💧 Su içme: Her saat başı (07:00-22:00)');
}

// MongoDB bağlantısı başarılı olduktan sonra scheduler'ı başlat
mongoose.connection.once('open', () => {
  if (firebaseInitialized && cron) {
    startReminderScheduler();
  } else {
    console.log('⚠️ Firebase veya cron hazır değil, scheduler başlatılmadı');
  }
});

// Start server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Server is running on port ${PORT}`);
});

