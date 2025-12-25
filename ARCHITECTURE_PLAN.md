# Sosyal Medya ve Mesajlaşma Uygulaması Backend Mimarisi Planı

## Genel Mimarik Bakış

Hedef: 100K concurrent kullanıcıyı destekleyen, yüksek performanslı, ölçeklenebilir ve güvenilir backend mimarisi

## VPS Dağılımı

### 1. DB VPS (Veritabanı Sunucusu)
- **İşlemci**: Yüksek çekirdekli (minimum 8 core)
- **RAM**: Minimum 32GB
- **Depolama**: SSD, yüksek IOPS
- **Kurulacak Teknolojiler**:
  - PostgreSQL 15+ (ana veritabanı)
  - Redis 7+ (cache, oturum yönetimi, mesaj kuyrukları)
  - PgBouncer (connection pooling)
  - Fail2Ban (güvenlik)
  - NTP (zaman senkronizasyonu)

### 2. Main VPS (Ana Uygulama Sunucusu)
- **İşlemci**: Yüksek çekirdekli (minimum 16 core)
- **RAM**: Minimum 64GB
- **Kurulacak Teknolojiler**:
  - Node.js 20+ (backend runtime)
  - PM2 (process yönetimi)
  - Socket.IO (gerçek zamanlı mesajlaşma)
  - Nginx (reverse proxy, load balancing)
  - Certbot (SSL sertifikaları)
  - Fail2Ban (güvenlik)
  - NTP (zaman senkronizasyonu)

## Backend Teknoloji Stack

### Uygulama Katmanı
- **Dil**: JavaScript/TypeScript
- **Framework**: Express.js veya Fastify (yüksek performans için)
- **WebSocket**: Socket.IO (scale-out desteği için Redis adapter kullanılacak)
- **Auth**: JWT + Refresh token sistemi
- **Rate Limiting**: Express-rate-limit veya hafif alternatifler
- **Logging**: Winston + ELK stack (opsiyonel)

### Veri Katmanı
- **Veritabanı**: PostgreSQL (kullanıcılar, gönderiler, gruplar, mesajlar vb.)
- **Cache**: Redis (oturumlar, sıklıkla erişilen veriler, geçici veriler)
- **Mesajlaşma**: WebSocket (Socket.IO) + Redis pub/sub (cluster desteği için)

## Ölçeklenebilirlik Stratejisi

### 1. Horizontal Scaling (Yatay Ölçekleme)
- Socket.IO kurulumu, Redis adapter ile cluster destekli olacak
- Uygulama sunucusu birden fazla instance'a bölünebilecek
- Nginx reverse proxy ile load balancing yapılacak

### 2. Database Scaling
- PostgreSQL üzerinde connection pooling (PgBouncer)
- Read replica'lar (gelecekte eklenebilir)
- Index optimizasyonları
- Partitioning (büyük tablolar için)

### 3. Cache Layer
- Redis üzerinde session yönetimi
- Sık erişilen verilerin cache'lenmesi
- Rate limiting için Redis kullanımı

## Mesajlaşma Mimarisi

### WebSocket (Socket.IO) ile Gerçek Zamanlı Mesajlaşma
- Kullanıcılar bağlandığında WebSocket bağlantısı kurulacak
- Her kullanıcıya uniq bir ID atanacak
- Mesajlar Redis pub/sub üzerinden farklı sunucular arasında iletilcek
- Socket.IO Redis adapter kullanılacak

### Mesaj Formatı
```json
{
  "id": "uuid",
  "senderId": "user_id",
  "recipientId": "user_id or group_id",
  "type": "text|image|video|audio|file",
  "content": "message_content",
  "timestamp": "ISO_date_string",
  "status": "sent|delivered|read"
}
```

## Güvenlik Önlemleri

### 1. Authentication & Authorization
- JWT token sistemi
- Refresh token ile güvenli oturum yönetimi
- Token'ların geçerlilik süreleri ve yenileme politikaları

### 2. Rate Limiting
- Her kullanıcı için API çağrısı limiti
- WebSocket bağlantı limiti
- DDOS koruma

### 3. Güvenlik Araçları
- Fail2Ban
- Güvenli HTTP başlıkları
- CORS politikaları
- Input validation

## Performans Optimizasyonları

### 1. Connection Management
- PostgreSQL için PgBouncer ile connection pooling
- WebSocket bağlantıları için uygun timeout ayarları
- Redis connection yönetimi

### 2. Caching
- Kullanıcı profilleri
- Sık erişilen içerikler
- Session verileri

### 3. Code Optimizations
- Asenkron işlemler
- Database sorgularının optimize edilmesi
- Index kullanımları

## Deployment Stratejisi

### 1. CI/CD
- GitHub Actions veya benzeri bir CI/CD pipeline
- Otomatik testler
- Blue-green deployment (gelecekte)

### 2. Monitoring
- PM2 monitoring
- PostgreSQL performans monitörleri
- Redis monitörleme
- Nginx log analizi

## Failover ve Yedekleme

### 1. Veritabanı Yedekleme
- Günlük otomatik yedeklemeler
- WAL archiving (kurtarma noktası için)
- Off-site yedekleme

### 2. Sunucu Yedekleme
- Sunucu snapshot'ları
- Anlık kurtarma planları
- DNS failover (gelecekte)

## Geliştirme Planı

### Aşama 1: Temel Mimarik Kurulum
- VPS'lerin hazırlanması
- Gerekli yazılımların kurulması
- Temel uygulama yapısının oluşturulması

### Aşama 2: Auth ve Temel API'ler
- Kullanıcı kaydı/girişi
- Temel API endpoint'leri
- JWT entegrasyonu

### Aşama 3: WebSocket ve Mesajlaşma
- Socket.IO kurulumu
- Gerçek zamanlı mesajlaşma
- Redis entegrasyonu

### Aşama 4: Ölçeklenebilirlik ve Performans
- Load balancing
- Cache entegrasyonları
- Performans testleri

### Aşama 5: Güvenlik ve İzleme
- Güvenlik önlemlerinin tamamlanması
- Monitörleme sistemlerinin kurulması
- Production hazır hale getirilmesi

## Load Testing Planı

- 10K concurrent kullanıcı simülasyonu
- 50K concurrent kullanıcı simülasyonu
- 100K concurrent kullanıcı simülasyonu
- WebSocket bağlantı testleri
- Database performans testleri

Bu plan, 100K concurrent kullanıcıyı destekleyecek bir backend mimarisi oluşturmak için temel yapı taşlarını içerir. Her aşamada performans ve güvenilirlik kriterlerine uygun olarak geliştirme yapılmalıdır.