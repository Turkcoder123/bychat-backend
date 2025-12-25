# Sosyal Medya ve Mesajlaşma Platformu Backend

Bu proje, 100.000 eşzamanlı kullanıcıyı desteklemek üzere tasarlanmış, yüksek performanslı bir sosyal medya ve mesajlaşma platformunun backend kısmını içerir.

## Mimari Plan

Detaylı mimari plan için [ARCHITECTURE_PLAN.md](ARCHITECTURE_PLAN.md) dosyasına bakabilirsiniz.

## Teknoloji Yığını

- **Backend**: Node.js (v20+)
- **Framework**: Express.js
- **Veritabanı**: PostgreSQL
- **Cache**: Redis
- **WebSocket**: Socket.IO (Redis adapter ile cluster destekli)
- **Reverse Proxy**: Nginx
- **Process Yönetimi**: PM2

## Kurulum

### Gereksinimler
- Node.js 20+
- PostgreSQL 15+
- Redis 7+
- Docker ve Docker Compose (isteğe bağlı)

### Geliştirme Ortamı Kurulumu

1. Gerekli bağımlılıkları yükleyin:
```bash
npm install
```

2. Ortam değişkenlerini yapılandırın:
```bash
cp .env.example .env
# .env dosyasını düzenleyin
```

3. Docker kullanarak bağımlılıkları başlatın:
```bash
docker-compose up -d
```

4. Uygulamayı başlatın:
```bash
npm run dev
```

### VPS Kurulumu

#### DB VPS (Veritabanı Sunucusu)
- PostgreSQL kurulumu
- Redis kurulumu
- PgBouncer (connection pooling)
- Güvenlik ayarları

#### Main VPS (Ana Uygulama Sunucusu)
- Node.js kurulumu
- PM2 kurulumu
- Socket.IO yapılandırması
- Nginx reverse proxy yapılandırması
- SSL sertifikası (Let's Encrypt)

## Özellikler

- Gerçek zamanlı mesajlaşma (WebSocket)
- 100K eşzamanlı kullanıcı desteği
- JWT tabanlı kimlik doğrulama
- Redis destekli oturum yönetimi
- Mesaj geçmişi ve sohbetler
- Kullanıcı çevrimiçi/offline durumu
- Yazıyor göstergesi
- Grup sohbetleri

## Performans Optimizasyonları

- PostgreSQL connection pooling (PgBouncer)
- Redis cache katmanı
- WebSocket bağlantı yönetimi
- Rate limiting
- Asenkron veritabanı işlemleri

## Katkıda Bulunma

1. Repository'yi fork edin
2. Yeni bir branch oluşturun (`git checkout -b feature/amazing-feature`)
3. Değişikliklerinizi yapın
4. Değişiklikleri commit edin (`git commit -m 'Add some amazing feature'`)
5. Branch'inize push edin (`git push origin feature/amazing-feature`)
6. Pull request oluşturun

## Lisans

Bu proje MIT lisansı ile lisanslanmıştır - detaylar için [LICENSE](LICENSE) dosyasına bakın.