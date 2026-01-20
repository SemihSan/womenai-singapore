# Women AI - Kadınlar İçin Yapay Zeka Asistanı

Cilt bakımı, beslenme, motivasyon ve daha fazlası için kişisel yapay zeka asistanınız.

## 🌐 Canlı Site
**https://womenai.semihcankadioglu.com.tr**

## 🚀 Kurulum

### Gereksinimler
- Node.js 18+
- MongoDB
- OpenAI API Key
- OpenWeatherMap API Key (opsiyonel)

### Adımlar

1. **Bağımlılıkları yükle:**
```bash
npm install
```

2. **Ortam değişkenlerini ayarla:**
```bash
cp .env.example .env
# .env dosyasını düzenle
```

3. **Sunucuyu başlat:**
```bash
# Development
npm run dev

# Production
npm run prod
```

## 📁 Dosya Yapısı

```
womenkopya/
├── index.html          # Ana sayfa
├── style.css           # Stiller
├── main.js             # Frontend JavaScript
├── server.js           # Backend API
├── admin-panel.html    # Admin paneli
├── favicon.svg         # Site ikonu
├── package.json        # Bağımlılıklar
├── .env.example        # Örnek ortam değişkenleri
└── .gitignore          # Git ignore
```

## 🔧 API Endpoints

| Endpoint | Method | Açıklama |
|----------|--------|----------|
| `/api/chat` | POST | Sohbet işlemleri (list, get, new, message, deleteAll) |
| `/api/weather` | GET | Hava durumu ve cilt analizi |
| `/admin` | GET | Admin paneli |
| `/health` | GET | Sağlık kontrolü |

## 🎨 Özellikler

- ✨ ChatGPT tarzı modern arayüz
- 🌙 Karanlık/Aydınlık tema desteği
- 💬 Gerçek zamanlı sohbet
- 🌤️ Hava durumu bazlı cilt analizi
- 🍃 Mod seçimi (Bakım, Motivasyon, Beslenme)
- 📱 Tam responsive tasarım

## 🔒 Güvenlik

- Helmet.js ile HTTP güvenlik başlıkları
- Rate limiting
- CORS koruması
- bcryptjs ile şifre hashleme

## 📝 Lisans

MIT License - Semih Can Kadıoğlu
