  // server.js
  require('dotenv').config();

  const express = require('express');
  const cors = require('cors');
  const mongoose = require('mongoose');
  const rateLimit = require('express-rate-limit');
  const helmet = require('helmet');
  const crypto = require('crypto');
  const bcrypt = require('bcryptjs');

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
  chatSchema.pre('save', function(next) {
    this.updatedAt = new Date();
    next();
  });

  // İlk mesajdan başlık oluştur
  chatSchema.methods.generateTitle = function() {
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
  adminUserSchema.pre('save', async function(next) {
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
  adminUserSchema.methods.comparePassword = async function(candidatePassword) {
    return await bcrypt.compare(candidatePassword, this.password);
  };

  const AdminUser = mongoose.model('AdminUser', adminUserSchema);

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
          if (!settings) settings = new AdminSettings();

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

          // Son 10 mesajı al
          const recentMessages = chat.messages.slice(-10).map((m) => ({ role: m.role, content: m.content }));

          const apiMessages = [
            { role: 'system', content: settings.systemPrompt || 'Sen bir kadın yaşam asistanısın.' },
            modePrompt ? { role: 'system', content: modePrompt } : null,
            ...recentMessages,
          ].filter(Boolean);

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

          let reply = 'Şu anda teknik bir sorun yaşıyorum, biraz sonra tekrar dener misin?';
          if (apiResponse.ok) {
            const data = await apiResponse.json();
            reply = data.choices?.[0]?.message?.content?.trim() || reply;
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

      return res.json({ ok: true, chat: {
        id: chat._id,
        title: chat.title,
        isFavorite: chat.isFavorite,
        isArchived: chat.isArchived,
        mode: chat.mode,
      }});
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

  // Health
  app.get('/health', (req, res) => res.json({ ok: true }));

  app.listen(PORT, () => {
    console.log(`🚀 Kadın AI Asistanı backend ${PORT} portunda dinliyor`);
  });

