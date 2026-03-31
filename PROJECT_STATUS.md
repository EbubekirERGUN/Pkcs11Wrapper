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
- Admin panel Phase D için config transfer dilimi teslim edildi: admin-only Configuration sayfası, JSON config export endpoint'i, merge / replace-all import modları, audit kayıtları ve device-profile-only güvenli bundle kapsamı eklendi.
- Admin panel için operator-facing PKCS#11 Lab sayfası eklendi: module info, interface discovery, slot snapshot, mechanism list/info, transient session info, RNG, digest ve object search operasyonları kontrollü biçimde denenebiliyor; request validation, audit logging ve protected PIN reuse desteği var.
- PKCS#11 Lab ikinci dalgası teslim edildi: sign/verify ve encrypt/decrypt denemeleri eklendi; handle + mechanism girişi, UTF-8/hex payload seçimi, signature/ciphertext alanları, parameterized mechanism uyarıları ve operator hata senaryolarını yakalayan validation kuralları eklendi.
- PKCS#11 Lab üçüncü dalgası teslim edildi: Inspect Object, Wrap Key ve constrained Unwrap AES Key operasyonları eklendi; Keys/Find Objects çıktısındaki handle'ların yeniden kullanılabildiği akışlar, unwrap hedef-template kontrolleri ve wrap/unwrap capability/policy uyarıları eklendi.
- PKCS#11 Lab dördüncü dalgası teslim edildi: Read Attribute operasyonu eklendi; ham attribute code ile status/length/raw-byte incelemesi yapılabiliyor. Ayrıca Keys ekranından Lab'a selected-object-assisted preset geçişleri eklendi; inspect/raw-attribute/sign/verify/encrypt/decrypt/wrap/unwrap akışları device/slot/handle/mechanism bağlamı prefilled açılabiliyor.
- PKCS#11 Lab beşinci dalgası teslim edildi: AES-CBC / AES-CTR / AES-GCM için parameter editor'ün ilk dilimi eklendi; crypto lab operasyonlarında IV/counter/AAD/tag alanları kullanılabiliyor. Read Attribute operasyonu multi-attribute/code-list batch desteği kazandı ve Keys/Lab preset mekanizma kodları wrapper sabitleriyle hizalandı.
- Admin panel uygulama katmanı için yeni doğrulama testleri eklendi; çözüm testleri ve hedefli admin web build doğrulaması temiz geçti.

## Şu an üzerinde çalışılan
- PKCS#11 Lab beşinci dalgası da tamamlandı; güvenlik/ops tarafında kalan iş bootstrap credential rotation UX'i, local user-management/maintenance akışı ve auth/ops dokümantasyonunun biraz daha ürünleştirilmesi.

## Sıradaki işler
- Bootstrap admin credential rotation / local user management UX'ini panel içine almak veya en azından kontrollü bir CLI/maintenance akışı tanımlamak.
- PKCS#11 Lab sayfasına altıncı dalgada daha ileri operasyonlar eklemek (ör. RSA OAEP/PSS parameter editor, selected-object preset wizard'ları, multi-step operation chaining / scenario recorder) ama bunu güvenli ve capability-aware tutmak.
- Phase D auth/ops dokümantasyonunu, config transfer kapsamı ve güvenlik sınırlarıyla birlikte biraz daha ürünleştirmek.
- Object copy akışına vendor-specific failure rehberi veya optional preset/template library katmanı düşünmek.
- PKCS#11 v3 message API'lerini gerçekten expose eden bir vendor/modül ile runtime regression eklemek.
- Gerekirse Windows runtime lane'ini GitHub üzerinde ilk gerçek koşusunda gözleyip paket/araç yolu ince ayarı yapmak.

## Riskler / blocker'lar
- Mevcut SoftHSM build'leri `C_GetInterface*` export etmediği için yeni v3 yüzeyin runtime pozitif doğrulaması henüz SoftHSM ile yapılamıyor; şimdilik ABI/layout + capability-gated davranış testleri var.
- Admin panel auth/secret yaklaşımı bu aşamada bilinçli olarak yerel dosya + Data Protection tabanlı tutuldu; harici IdP/KMS entegrasyonu yok. Bu, tek hostlu gömülü yönetim paneli için pratik ama tam production IAM/secret-vault çözümü değil.

## Commit / push durumu
- `v0.1.0` release GitHub'da yayınlandı.
- Admin panel PKCS#11 Lab beşinci dalga slice'ı yerelde değişiklik olarak duruyor; henüz commit/push yapılmadı.
