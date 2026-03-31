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
- Admin panel Phase B için ilk anlamlı genişleme tamamlandı: key/object detail paneli, AES key generate akışı, RSA keypair generate akışı ve typed confirmation + kalıcı silme onayı isteyen daha güvenli destroy UX'i eklendi.
- Admin panel Phase B/C devamı işlendi: AES raw-value import/create akışı, desteklenen alanlar için object attribute editing paneli, daha güvenli key/object UX iyileştirmeleri, richer tracked-session detail görünümü, tracked session üzerinde login/logout kontrolleri, `C_SessionCancel` yüzeyi ve slot bazlı `CloseAllSessions` tetikleme eklendi.
- Admin panel uygulama katmanı için yeni doğrulama testleri eklendi; çözüm testleri ve hedefli admin web build doğrulaması temiz geçti.

## Şu an üzerinde çalışılan
- Admin panelde yeni eklenen Phase B/C slice'ının son gözden geçirmesi ve sonraki dilimin planlanması.

## Sıradaki işler
- Admin panelde token capability/mechanism bilgisini kullanarak edit/import formlarını daha öngörülü hale getirmek.
- Session ekranında grouped/filterable görünüm ve invalidated tracked session'lar için daha belirgin UX düşünmek.
- PKCS#11 v3 message API'lerini gerçekten expose eden bir vendor/modül ile runtime regression eklemek.
- Gerekirse Windows runtime lane'ini GitHub üzerinde ilk gerçek koşusunda gözleyip paket/araç yolu ince ayarı yapmak.

## Riskler / blocker'lar
- Mevcut SoftHSM build'leri `C_GetInterface*` export etmediği için yeni v3 yüzeyin runtime pozitif doğrulaması henüz SoftHSM ile yapılamıyor; şimdilik ABI/layout + capability-gated davranış testleri var.

## Commit / push durumu
- Yerel değişiklikler mevcut; bu admin panel Phase B slice'ı commitlenecek, push yapılmadı.
