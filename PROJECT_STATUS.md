# PROJECT_STATUS

## Tamamlananlar
- Faz 1.1, 1.2, 1.3, 1.4 daha önce tamamlandı.
- Faz 1.5 kapsamında mechanism matrix genişletildi.
- AES-CTR ve AES-CBC-PAD için yeni SoftHSM regression testleri eklendi.
- Negatif senaryolarda hatalı mechanism parametrelerinin capability-gated / açık assert ile ele alındığı doğrulandı.
- `PROJECT_ROADMAP.md` güncellendi.

## Şu an üzerinde çalışılan
- Faz 2.1: `C_GetInterface` / `C_GetInterfaceList` için PKCS#11 v3 function-list erişim tasarımının çıkarılması.

## Sıradaki işler
- Faz 2.1 interface discovery implementasyonu
- Faz 2.2 message-based PKCS#11 v3 API yüzeyi
- Faz 2.3 `C_LoginUser` ve `C_SessionCancel`
- Faz 3.1 / 3.2 / 3.3 dokümantasyon ve release disiplini

## Riskler / blocker'lar
- PKCS#11 v3 API'leri normal `C_GetFunctionList()` yerine `C_GetInterface()` ile alınan 3.0 function list üzerinden geldiği için interop tasarımı dikkat istiyor.
- Yanlış struct layout, mevcut 2.x yüzeyini bozabileceğinden Faz 2 dikkatli ve parça parça doğrulanmalı.

## Commit / push durumu
- Yerel değişiklikler var, henüz push yok.
