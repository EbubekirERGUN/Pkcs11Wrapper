# PROJECT_STATUS

## Tamamlananlar
- .NET SDK pin'i `10.0.201` seviyesine çıkarıldı; user-local runtime/SDK ile çözüm restore/build/test akışı doğrulandı.
- İngilizce/Türkçe README dosyaları güncel ürün konumlandırması, benchmark görünürlüğü ve admin panel yetenekleriyle senkron tutuluyor.
- GitHub topluluk/sağlık dosyaları eklendi: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue template'leri ve PR template.
- `docs/github-showcase.md` ile repo metadata/vitrin yönlendirmesi eklendi.
- Faz 1.1–1.5 tamamlandı; initialize flow, lifecycle/concurrency hardening, vendor regression lane disiplini ve mechanism matrix genişletmeleri teslim edildi.
- Faz 2.1–2.3 tamamlandı; `C_GetInterface` / `C_GetInterfaceList`, PKCS#11 v3 message API yüzeyi, `C_LoginUser` ve `C_SessionCancel` eklendi.
- Faz 3.1–3.3 tamamlandı; compatibility/release dokümantasyonu, package metadata, release verification ve merkezi versioning (`0.1.0`) oturtuldu.
- `v0.1.0` release GitHub'da yayınlandı; paketler ve checksum'lar release asset olarak yüklendi.
- Windows desteği iki dilimde güçlendirildi: platform-aware module path helper, Windows CI build/runtime lane, SoftHSM-for-Windows fixture/bootstrap script'leri ve Windows smoke/regression akışları teslim edildi.
- Blazor Server admin panel iskeleti ve sonraki dikey dilimler teslim edildi:
  - device profile CRUD
  - connection test
  - slot/token browsing
  - key/object listing + detail/edit/copy/generate/import/destroy akışları
  - tracked session registry + login/logout/cancel/close-all + invalidation görünürlüğü
  - append-only chained audit log + integrity doğrulaması
  - protected PIN cache
  - admin-only configuration export/import
  - local cookie auth + `viewer` / `operator` / `admin` rol modeli
  - local user management, password rotation ve bootstrap credential lifecycle kontrolleri
- PKCS#11 Lab yedi dalga halinde teslim edildi:
  - diagnostics / discovery
  - crypto ops (sign/verify, encrypt/decrypt)
  - object workflows (inspect, wrap, constrained unwrap)
  - raw attribute reads + selected-object presets
  - AES parameter editor support
  - RSA OAEP/PSS parameter editor support
  - scenario history / replay / chaining / preset library
- BenchmarkDotNet tabanlı performans benchmark suite'i eklendi:
  - benchmark projesi `benchmarks/Pkcs11Wrapper.Benchmarks`
  - Linux/Windows benchmark script'leri
  - haftalık + manuel benchmark workflow'u
  - `docs/benchmarks.md`
  - commitlenmiş son Linux + SoftHSM baseline: `docs/benchmarks/latest-linux-softhsm.md`
- Admin panel Phase E ilk polish dilimi teslim edildi:
  - dashboard health/ops summary kartları ve quick-action yüzeyi
  - audit sayfasında filtreleme + paging
  - users sayfasında özet kartları, arama, rol filtresi ve sıralama
  - `docs/admin-ops-recovery.md` ile local operations/recovery runbook
- Admin panel Phase E ikinci polish dilimi teslim edildi:
  - devices sayfasında özet kartları, arama, status filtresi ve sıralama
  - slots sayfasında özet kartları, token filtresi, sıralama ve seçili cihaza göre tracked-session görünümü
  - sessions sayfasında özet kartları, search/device/health filtreleri, sıralama ve filtered/invalidated bulk-close ergonomisi
- Admin panel Phase E üçüncü polish dilimi teslim edildi:
  - keys/objects ekranında özet kartları, client-side search/class/capability filtreleri, sıralama ve paging
  - load-time label filter ile loaded-view filtrelerinin ayrıştırılması
  - `KeyObjectListView` helper + testler ile keys table ergonomisinin testlenebilir hale getirilmesi
- Çözüm doğrulaması temiz:
  - `dotnet build Pkcs11Wrapper.sln -c Release`
  - `dotnet test Pkcs11Wrapper.sln -c Release`
  - benchmark suite çalışıyor ve README'de tarihli son baseline gösteriliyor.

## Şu an üzerinde çalışılan
- Aktif kod blocker'ı yok.
- Belgeleme senkronizasyonu yapıldı; README'ler artık admin panelin auth/users/config-transfer/PKCS#11 Lab gerçek durumunu ve benchmark baseline tarihini yansıtıyor.

## Sıradaki işler
- Admin panel UX/product polish'in sonraki dilimleri (Configuration/Lab gibi yoğun operasyon ekranlarında benzer ergonomi, dashboard/widget genişletmeleri, recovery affordance polish).
- PKCS#11 v3 interface yüzeyini gerçekten export eden vendor/modül ile ek runtime regression.
- Benchmark suite'i performans hassas değişikliklerden sonra ve release öncesinde tekrar çalıştırıp en güncel baseline'ı tazelemek.
- GitHub vitrin materyallerini zenginleştirmek (ekran görüntüsü, demo media, release notes).
- İstenirse PKCS#11 Lab için sekizinci dalgada daha ileri ama hâlâ kontrollü operasyon setleri eklemek.

## Riskler / blocker'lar
- PKCS#11 v3 runtime davranışı hâlâ hedef modülün ilgili interface surface'i export etmesine bağlı; SoftHSM bu konuda sınırlı.
- Admin panel security modeli bilinçli olarak local-host odaklı; external IdP/IAM, MFA ve merkezi secret governance henüz kapsamda değil.
- Benchmark sonuçları host, CPU, OS, module ve fixture koşullarına bağlıdır; GitHub'da gösterilen baseline karşılaştırma için faydalıdır ama mutlak evrensel hız iddiası değildir.

## Commit / push durumu
- `origin/main` benchmark suite, README benchmark tarih güncellemesi ve .NET `10.0.201` SDK pin upgrade'ine kadar güncel durumda.
- Bu dosya/README senkronizasyonu yerelde güncellenmiştir; yeni push ayrıca istenirse yapılır.
- Scratch dosyaları `.reflection.txt` ve `.sig_extract.txt` commit/push kapsamı dışında tutulmaya devam ediyor.
