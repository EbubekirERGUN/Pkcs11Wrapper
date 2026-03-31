# PROJECT_STATUS

## Tamamlananlar
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
- Post-roadmap enhancement olarak Windows desteği güçlendirildi: platforma göre bilinen SoftHSM modül adı helper'ı eklendi, smoke sample bu helper'ı kullanacak şekilde güncellendi, Windows CI build/API/layout lane'i eklendi ve dokümantasyon Windows build/runtime beklentileriyle senkronlandı.
- Windows desteği ikinci adımda daha da ileri taşındı: gerçek SoftHSM-for-Windows fixture bootstrap script'i (`eng/setup-softhsm-fixture.ps1`), Windows regression/smoke script'leri (`eng/run-regression-tests.ps1`, `eng/run-smoke.ps1`), Windows CI runtime regression lane'i, `docs/windows-local-setup.md` ve `docs/release-notes/windows-compatibility.md` eklendi.
- `PROJECT_ROADMAP.md` güncellendi.
- Yeni bir Blazor Server admin panel girişimi başlatıldı: `Pkcs11Wrapper.Admin.Application`, `Pkcs11Wrapper.Admin.Infrastructure`, `Pkcs11Wrapper.Admin.Web` ve `Pkcs11Wrapper.Admin.Tests` projeleri çözüme eklendi.
- Admin panelin ilk iskeleti kuruldu: device profile CRUD, connection test, slot listeleme, key/object listeleme + explicit destroy akışı, uygulama-owned session registry, audit log görünümü ve dashboard ekranı eklendi.
- Admin panel için başlangıç yol haritası `docs/admin-panel-roadmap.md` içinde oluşturuldu.

## Şu an üzerinde çalışılan
- Blazor Server admin panelinin ilk iskeleti tamamlandı; build/test/self-review doğrulaması alındı.

## Sıradaki işler
- Admin panel Phase B: key/object detail, generate/create akışları ve daha güvenli destructive işlemler.
- Admin panel Phase C: daha zengin session operasyonları ve login/logout görünürlüğü.
- PKCS#11 v3 message API'lerini gerçekten expose eden bir vendor/modül ile runtime regression eklemek.
- Gerekirse Windows runtime lane'ini GitHub üzerinde ilk gerçek koşusunda gözleyip paket/araç yolu ince ayarı yapmak.

## Riskler / blocker'lar
- Mevcut SoftHSM build'leri `C_GetInterface*` export etmediği için yeni v3 yüzeyin runtime pozitif doğrulaması henüz SoftHSM ile yapılamıyor; şimdilik ABI/layout + capability-gated davranış testleri var.

## Commit / push durumu
- Yerel değişiklikler var; admin panel scaffold'ı ve ilgili proje/doküman değişiklikleri için henüz push yok.
