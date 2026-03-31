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
- `PROJECT_ROADMAP.md` güncellendi.

## Şu an üzerinde çalışılan
- Windows desteği değişikliklerinin self-review ve doğrulaması tamamlandı.

## Sıradaki işler
- PKCS#11 v3 message API'lerini gerçekten expose eden bir vendor/modül ile runtime regression eklemek.
- Gerekirse smoke veya örnek uygulamaya v3-capable bir örnek akış eklemek.
- Yayın politikası netleşirse tag-only publish otomasyonu düşünmek.
- Gerekirse Windows tarafında gerçek bir PKCS#11 modül/fixture ile pozitif runtime regression eklemek.

## Riskler / blocker'lar
- Mevcut SoftHSM build'leri `C_GetInterface*` export etmediği için yeni v3 yüzeyin runtime pozitif doğrulaması henüz SoftHSM ile yapılamıyor; şimdilik ABI/layout + capability-gated davranış testleri var.

## Commit / push durumu
- Yerel değişiklikler var; Windows desteği değişikliği için henüz push yok.
