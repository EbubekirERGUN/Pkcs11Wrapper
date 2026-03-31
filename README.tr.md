# Pkcs11Wrapper

[English](README.md) | Turkce

`Pkcs11Wrapper`, yerel bir Cryptoki modulu uzerinde kucuk ve acik bir yonetilen API sunan .NET 10 tabanli bir PKCS#11 wrapper projesidir. Proje cross-platform .NET kullanimini hedefler; Linux tarafinda SoftHSM ile daha derin dogrulanir, Windows tarafinda gercek SoftHSM runtime regression akisina sahiptir, NativeAOT ile uyumludur ve GitHub odakli restore/build/test/smoke akislarina gore duzenlenmistir.

Bu README depo seviyesi is akislarini ozetler. Uygulama ayrintilari ve gelistirici notlari icin `docs/` altindaki dokumanlara bakin.

## Proje kapsami

Mevcut wrapper ve dogrulama kapsaminda sunlar bulunur:

- Modul yasam dongusu: load, initialize, finalize, module info
- Opsiyonel initialize aninda `CK_C_INITIALIZE_ARGS` bayraklari ve ozel mutex callback baglama destegi
- Slot, token ve mechanism listeleme
- Session acma/kapama ile user ve security-officer login akislar
- `C_GetInterface` / `C_GetInterfaceList` uzerinden opsiyonel PKCS#11 v3 interface discovery
- Object search ile attribute read/write yardimcilari
- Object create, update, size query ve destroy akislar
- Single-part encrypt/decrypt islemleri
- Multi-part encrypt/decrypt ve operation-state resume akislar
- Sign/verify islemleri
- Modul bir v3 interface expose ediyorsa PKCS#11 v3 message-based encrypt/decrypt/sign/verify API'leri
- Yonetimsel operasyonlar: `CloseAllSessions`, `InitPin`, `SetPin`, `InitToken`
- Modul bir v3 interface expose ediyorsa PKCS#11 v3 session operasyonlari: `C_LoginUser`, `C_SessionCancel`
- Hata raporlama yuzeyi: taxonomy metadata (retryability ipucu dahil) ve ham `CK_RV` korunumu
- Dogrulama varliklari: SoftHSM fixture provisioning, regression script'leri, NativeAOT smoke, GitHub Actions CI, release verification script'i, NuGet pack metadata

GitHub Actions tarafinda push/PR icin varsayilan Linux yolu SoftHSM olarak kalir; buna ek olarak Windows SoftHSM runtime regression lane'i ve bakimcilar icin manuel tetiklenen opsiyonel vendor PKCS#11 regression lane de bulunur. Kurulum ayrintilari `docs/ci.md`, vendor lane sozlesmesi `docs/vendor-regression.md`, release dogrulama akisi ise `docs/release.md` icindedir.

`InitToken` regression kapsami vardir; ancak provisioning odakli bu dogrulama, her genel calistirma senaryosunun zorunlu parcasi degil, opt-in bir yoldur.

## Guncel kisitlar (izlenen)

- Otomatik runtime dogrulama henuz PKCS#11 v3 message API'lerini pozitif olarak expose eden bir modul icermiyor; bu yollar su an ABI/layout testleri ve capability-gated runtime davranisi ile korunuyor.
- Typed mechanism parameter helper/marshalling ECDH, AES-GCM/CTR/CCM ve RSA-OAEP/PSS yollarini kapsar; daha az yaygin bazi mechanism'ler halen ham byte payload kullanabilir.
- Linux halen en derin runtime dogrulamaya sahiptir (fixture-backed regression + NativeAOT smoke); Windows ise artik SoftHSM-for-Windows uzerinden fixture-backed runtime regression sunar, ancak henuz NativeAOT smoke esdegerine sahip degildir.
- Paket yayini halen maintainer kontrollu bir aksiyondur; otomatik publish adimi tanimli degildir.

## Gereksinimler

- `global.json` ile sabitlenen .NET SDK `10.0.104`
- Dokumante edilen tam fixture-backed smoke/regression akislar icin Linux ortami
- Windows, build/test kullanimi ve acik bir PKCS#11 modul yolu veya bilinen SoftHSM-for-Windows modul adi ile runtime kullanimi icin desteklenir
- SoftHSM v2 kutuphanesi ve araclari
- OpenSC `pkcs11-tool`
- NativeAOT smoke script'i icin `file`
- Muhendislik script'leri icin `bash` ve `python3`

CI tarafinda kullanilan Ubuntu/Debian paket kurulumu:

```bash
sudo apt-get update
sudo apt-get install -y softhsm2 opensc file
```

## Hizli baslangic

1. Cozumu restore edip build alin:

```bash
dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
```

2. Gecici bir SoftHSM fixture olusturun ve uretilen ortam dosyasini yukleyin:

```bash
./eng/setup-softhsm-fixture.sh
source /tmp/path-from-script/pkcs11-fixture.env
```

Kurulum script'i tam env dosyasi yolunu ekrana yazar. Fixture gecicidir; yerel dogrulama ve CI benzeri calismalar icin tasarlanmistir.

3. Regression akisini calistirin:

```bash
./eng/run-regression-tests.sh
```

4. Smoke ornegini dogrudan calistirin:

```bash
dotnet run --project samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release
```

5. NativeAOT smoke akisini calistirin:

```bash
./eng/run-smoke-aot.sh
```

## Temel komutlar

```bash
dotnet restore Pkcs11Wrapper.sln
dotnet build Pkcs11Wrapper.sln -c Release --no-restore
dotnet test Pkcs11Wrapper.sln -c Release --nologo --logger "console;verbosity=minimal"
./eng/setup-softhsm-fixture.sh
./eng/run-regression-tests.sh
dotnet run --project samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj -c Release
./eng/run-smoke-aot.sh
```

## Dokuman haritasi

- `docs/development.md` - depo yapisi, yerel gelistirme dongusu, test katmanlari, ozellik durumu
- `docs/softhsm-fixture.md` - SoftHSM fixture sozlesmesi, ekilen objeler, env override'lari, temizlik davranisi
- `docs/ci.md` - GitHub Actions CI akisi ve yerel esdeger calistirma notlari
- `docs/vendor-regression.md` - vendor uyumluluk profili, gerekli env sozlesmesi, capability-gated ve hard-fail ayrimi
- `docs/smoke.md` - smoke orneginin davranisi, ortam degiskenleri, beklenen basari ciktilari, sorun giderme
- `docs/windows-local-setup.md` - SoftHSM-for-Windows ve OpenSC ile yerel Windows fixture/bootstrap akisi
- `docs/compatibility-matrix.md` - dogrulanmis baseline, desteklenen capability alanlari, bilinen kisitlar
- `docs/release.md` - release checklist, versiyonlama rehberi, packaging notlari

## Onemli yollar

- `Pkcs11Wrapper.sln`
- `src/Pkcs11Wrapper/Pkcs11Wrapper.csproj`
- `src/Pkcs11Wrapper.Native/Pkcs11Wrapper.Native.csproj`
- `tests/Pkcs11Wrapper.Native.Tests/Pkcs11Wrapper.Native.Tests.csproj`
- `samples/Pkcs11Wrapper.Smoke/Pkcs11Wrapper.Smoke.csproj`
- `eng/setup-softhsm-fixture.sh`
- `eng/run-regression-tests.sh`
- `eng/run-smoke-aot.sh`
- `.github/workflows/ci.yml`
