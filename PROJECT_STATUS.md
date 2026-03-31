# PROJECT_STATUS

## Tamamlananlar
- README İngilizce/Türkçe dosyaları GitHub vitrini odaklı olarak yeniden düzenlendi; badge'ler, feature highlights, quick start, architecture diyagramı, docs map ve roadmap snapshot eklendi.
- GitHub topluluk/sağlık dosyaları eklendi: `CONTRIBUTING.md`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, issue template'leri ve PR template.
- Repository settings tarafında uygulanmak üzere `docs/github-showcase.md` oluşturuldu.
- Faz 1.1, 1.2, 1.3, 1.4 daha önce tamamlandı.
- Faz 1.5 kapsamında mechanism matrix genişletildi.
- AES-CTR ve AES-CBC-PAD için yeni SoftHSM regression testleri eklendi.
- Negatif senaryolarda hatalı mechanism parametrelerinin capability-gated / açık assert ile ele alındığı doğrulandı.
- Faz 2.1 tamamlandı: `C_GetInterface` / `C_GetInterfaceList` için optional export tabanlı interface discovery ve managed `Pkcs11Interface` projeksiyonu eklendi.
- Faz 2.2 tamamlandı: PKCS#11 v3 message-based encrypt/decrypt/sign/verify API yüzeyi span-first biçimde eklendi.
- Faz 2.3 tamamlandı: `C_LoginUser` ve `C_SessionCancel` session yüzeyine eklendi.
- Faz 3.1 tamamlandı: `docs/compatibility-matrix.md` ile destek/limitasyon matrisi yazıldı.
- Faz 3.2 tamamlandı: geliştirme dokümanı v3 capability-gated davranış ve yeni dokümanlarla güncellendi.
- Faz 3.3 tamamlandı: package metadata ve `eng/verify-release.sh` release doğrulama akışı eklendi.
- Merkezi `0.1.0` versioning kuruldu: `Directory.Build.props` artık repository/package sürümünün tek kaynağı, `docs/versioning.md` ve `docs/release-notes/v0.1.0.md` eklendi, `eng/verify-release.sh` repo sürümüyle hizalı paket üretimi yapacak şekilde güncellendi ve `Pkcs11Wrapper.0.1.0.nupkg` ile `Pkcs11Wrapper.Native.0.1.0.nupkg` başarıyla doğrulandı.
- Post-roadmap enhancement olarak Windows desteği güçlendirildi: platforma göre bilinen SoftHSM modül adı helper'ı eklendi, smoke sample bu helper'ı kullanacak şekilde güncellendi, Windows CI build/API/layout lane'i eklendi ve dokümantasyon Windows build/runtime beklentileriyle senkronlandı.
- Windows desteği ikinci adımda daha da ileri taşındı: gerçek SoftHSM-for-Windows fixture bootstrap script'i (`eng/setup-softhsm-fixture.ps1`), Windows regression/smoke script'leri (`eng/run-regression-tests.ps1`, `eng/run-smoke.ps1`), Windows CI runtime regression lane'i, `docs/windows-local-setup.md` ve `docs/release-notes/windows-compatibility.md` eklendi.
- `PROJECT_ROADMAP.md` güncellendi.
- Yeni bir Blazor Server admin panel girişimi başlatıldı: `Pkcs11Wrapper.Admin.Application`, `Pkcs11Wrapper.Admin.Infrastructure`, `Pkcs11Wrapper.Admin.Web` ve `Pkcs11Wrapper.Admin.Tests` projeleri çözüme eklendi.
- Admin panelin ilk iskeleti kuruldu: device profile CRUD, connection test, slot listeleme, key/object listeleme + explicit destroy akışı, uygulama-owned session registry, audit log görünümü ve dashboard ekranı eklendi.
- Admin panel için başlangıç yol haritası `docs/admin-panel-roadmap.md` içinde oluşturuldu.
- Admin panel Phase B için ilk anlamlı genişleme tamamlandı: key/object detail paneli, AES key generate akışı, RSA keypair generate akışı ve typed confirmation + kalıcı silme onayı isteyen daha güvenli destroy UX'i eklendi.
- Admin panel Phase B/C devamı işlendi: AES raw-value import/create akışı, desteklenen alanlar için object attribute editing paneli, daha güvenli key/object UX iyileştirmeleri, richer tracked-session detail görünümü, tracked session üzerinde login/logout kontrolleri, `C_SessionCancel` yüzeyi ve slot bazlı `CloseAllSessions` tetikleme eklendi.
- Admin panel için sıradaki üç UX iyileştirme slice'ı tamamlandı: slot capability/mechanism keşfi ile generate/import aksiyonları pre-submit gated hale getirildi, object edit ekranı obje sınıfı + `CKA_MODIFIABLE` görünürlüğüne göre obvious unsupported toggle'ları kapatacak şekilde güçlendirildi, tracked session'larda invalidation reason/health labeling/grouped filtering eklendi ve `C_CopyObject` tabanlı yeni object copy akışı teslim edildi.
- Admin panel Phase D güvenlik hardening'i başlatıldı ve ilk üç öncelik teslim edildi: local cookie auth + viewer/operator/admin rol modeli, servis katmanında yetki doğrulaması, PIN'ler için Data Protection-backed protected local storage ve hash-chained/metadata-rich audit log bütünlük doğrulaması eklendi.
- Admin panel uygulama katmanı için yeni doğrulama testleri eklendi; çözüm testleri ve hedefli admin web build doğrulaması temiz geçti.

## Şu an üzerinde çalışılan
- Admin panelde Phase D hardening slice'ının ilk bölümü tamamlandı; kalan iş Phase D içinde config export/import, bootstrap credential rotation UX'i ve auth/ops dokümantasyonunun biraz daha ürünleştirilmesi.

## Sıradaki işler
- Admin panel için config export/import dilimini eklemek ve Phase D'yi kapatmak.
- Bootstrap admin credential rotation / local user management UX'ini panel içine almak veya en azından kontrollü bir CLI/maintenance akışı tanımlamak.
- Object copy akışına vendor-specific failure rehberi veya optional preset/template library katmanı düşünmek.
- PKCS#11 v3 message API'lerini gerçekten expose eden bir vendor/modül ile runtime regression eklemek.
- Gerekirse Windows runtime lane'ini GitHub üzerinde ilk gerçek koşusunda gözleyip paket/araç yolu ince ayarı yapmak.

## Riskler / blocker'lar
- Mevcut SoftHSM build'leri `C_GetInterface*` export etmediği için yeni v3 yüzeyin runtime pozitif doğrulaması henüz SoftHSM ile yapılamıyor; şimdilik ABI/layout + capability-gated davranış testleri var.
- Admin panel auth/secret yaklaşımı bu aşamada bilinçli olarak yerel dosya + Data Protection tabanlı tutuldu; harici IdP/KMS entegrasyonu yok. Bu, tek hostlu gömülü yönetim paneli için pratik ama tam production IAM/secret-vault çözümü değil.

## Commit / push durumu
- `0.1.0` versioning çalışması yerelde commitlenecek; push yapılmadı.
