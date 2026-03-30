# Pkcs11Wrapper

[English](README.md) | Turkce

`Pkcs11Wrapper`, yerel bir Cryptoki modulu uzerinde kucuk ve acik bir yonetilen API sunan .NET 10 tabanli bir PKCS#11 wrapper projesidir. Proje Linux-first yaklasimla ilerler, SoftHSM ile dogrulanir, NativeAOT ile uyumludur ve GitHub odakli restore/build/test/smoke akislarina gore duzenlenmistir.

Bu README depo seviyesi is akislarini ozetler. Uygulama ayrintilari ve gelistirici notlari icin `docs/` altindaki dokumanlara bakin.

## Proje kapsami

Mevcut wrapper ve dogrulama kapsaminda sunlar bulunur:

- Modul yasam dongusu: load, initialize, finalize, module info
- Slot, token ve mechanism listeleme
- Session acma/kapama ile user ve security-officer login akislar
- Object search ile attribute read/write yardimcilari
- Object create, update, size query ve destroy akislar
- Single-part encrypt/decrypt islemleri
- Multi-part encrypt/decrypt ve operation-state resume akislar
- Sign/verify islemleri
- Yonetimsel operasyonlar: `CloseAllSessions`, `InitPin`, `SetPin`, `InitToken`
- Hata raporlama yuzeyi: taxonomy metadata (retryability ipucu dahil) ve ham `CK_RV` korunumu
- Dogrulama varliklari: SoftHSM fixture provisioning, regression script'leri, NativeAOT smoke, GitHub Actions CI

GitHub Actions tarafinda push/PR icin varsayilan yol SoftHSM olarak kalir; bakimcilar icin manuel tetiklenen opsiyonel bir vendor PKCS#11 regression lane de bulunur. Kurulum ayrintilari `docs/ci.md` icindedir.

`InitToken` regression kapsami vardir; ancak provisioning odakli bu dogrulama, her genel calistirma senaryosunun zorunlu parcasi degil, opt-in bir yoldur.

## Gereksinimler

- `global.json` ile sabitlenen .NET SDK `10.0.104`
- Dokumante edilen yerel ve CI akislar icin Linux ortami
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
- `docs/smoke.md` - smoke orneginin davranisi, ortam degiskenleri, beklenen basari ciktilari, sorun giderme

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
