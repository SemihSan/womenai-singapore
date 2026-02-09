# Mobil Uygulama Entegrasyon Rehberi (Flutter)

Mevcut web uygulamanı (özellikle Cilt Bakımı ve Su Hatırlatıcısı özelliklerini) koruyarak bir mobil uygulamaya dönüştürmek için **Hybrid (WebView + Native FCM)** yaklaşımını öneriyorum.

Bu yaklaşımda:
1.  **Görünüm (UI):** Web siten birebir `WebView` içinde çalışır. Tasarım değişikliğine gerek kalmaz.
2.  **Bildirimler:** Arka planda çalışması gerektiği için (su/cilt hatırlatıcıları) **Native** katmanda (Flutter) çalışır.
3.  **İletişim:** Web sitesi ile Mobil uygulama birbiriyle konuşur (JavaScript Bridge).

---

## 1. Backend Düzenlemesi (Server.js)

`server.js` dosyasında `/api/push/subscribe` endpoint'inin mobil cihaz bilgisini (`device`) alabilmesi lazım. Şu an sadece `userAgent` kaydediyor.

**Yapılacak Değişiklik:** `server.js` içinde `req.body`'den `device` parametresini alıp veritabanına kaydetmesini sağlayacağız. (Bunu senin için yapabilirim).

## 2. Flutter Proje Yapısı

Yeni bir Flutter projesi oluştur ve şu paketleri ekle (`pubspec.yaml`):

```yaml
dependencies:
  flutter:
    sdk: flutter
  webview_flutter: ^4.0.0  # Web sitesini göstermek için
  firebase_core: ^2.0.0    # Firebase bağlantısı
  firebase_messaging: ^14.0.0 # Bildirim almak için
  shared_preferences: ^2.0.0 # Token saklamak için
  http: ^1.0.0 # Backend'e istek atmak için
```

## 3. Mantık Akışı (Workflow)

Mobil uygulama açıldığında şu sırayla çalışacak:

### A. Uygulama Başlatma & WebView
Uygulama açılır açılmaz Web siteni tam ekran yükle.

```dart
WebViewWidget(
  controller: WebViewController()
    ..setJavaScriptMode(JavaScriptMode.unrestricted)
    ..addJavaScriptChannel(
      'FlutterApp', // Web'den mesaj dinleyen kanal
      onMessageReceived: (message) {
        // Web'den User ID geldiğinde tetiklenir
        _registerWithBackend(message.message); 
      },
    )
    ..loadRequest(Uri.parse('https://singapur.semihcankadioglu.com.tr')),
)
```

### B. Oturum Açma Tespiti (JavaScript Bridge)
Kullanıcı web sitesinde "Google ile Giriş Yap" dediğinde, Web siten giriş başarılı olunca Flutter'a haber vermeli.

Web sitendeki `main.js` veya giriş başarılı olan yere şu kodu ekleyeceğiz:

```javascript
// Web tarafındaki kod (Giriş başarılı olduğunda çalışacak)
if (window.FlutterApp) {
  // Mobile kullanıcı ID'sini gönder
  window.FlutterApp.postMessage(userId);
}
```

### C. Bildirim İzni ve Token Alma (Native)
Flutter tarafında (Native), kullanıcıdan bildirim izni iste ve FCM Token al.

```dart
FirebaseMessaging messaging = FirebaseMessaging.instance;

// İzin iste
NotificationSettings settings = await messaging.requestPermission(
  alert: true,
  badge: true,
  sound: true,
);

// Token al
String? fcmToken = await messaging.getToken();
```

### D. Backend'e Kayıt (Subscribe)
Web'den `userId` geldiğinde ve `fcmToken` alındığında, senin mevcut API'ne istek at.

```dart
void _registerWithBackend(String userId) async {
  String? fcmToken = await FirebaseMessaging.instance.getToken();
  
  var response = await http.post(
    Uri.parse('https://singapur.semihcankadioglu.com.tr/api/push/subscribe'),
    headers: {"Content-Type": "application/json"},
    body: jsonEncode({
      "userId": userId,
      "fcmToken": fcmToken,
      "device": "android", // veya "ios",Platform.isAndroid ? 'android' : 'ios'
      // İsteğe bağlı: varsayılan tercihler
      "preferences": {
        "skincare": true,
        "water": true
      }
    }),
  );
}
```

## 4. Bildirimleri Gösterme
`server.js` zaten Firebase Admin SDK kullanıyor. Mobil tarafta:
*   Uygulama **Açıkken (Foreground):** `FirebaseMessaging.onMessage.listen` ile bildirimi yakalayıp kendin bir Dialog veya Snack bar gösterirsin.
*   Uygulama **Kapalıyken/Arka Planda:** Firebase SDK otomatik olarak sistem tepsisine (Notification Tray) bildirimi düşürür. Ekstra kod yazmana gerek kalmaz (Server doğru payload gönderdiği sürece).

## 5. Özet: Yapman Gerekenler

1.  **Server.js:** `device` parametresini kabul edecek şekilde güncelle (Ben yapabilirim).
2.  **Web Frontend:** Giriş işlemi bitince `window.FlutterApp.postMessage(userId)` satırını ekle.
3.  **Flutter:** Projeyi kur, WebView ve Firebase Messaging entegrasyonunu yukarıdaki gibi yap.

Bu yapı ile web sitendeki tüm özellikler mobilde çalışırken, hatırlatıcılar %100 kararlı bir şekilde telefon bildirimlerine düşer.
