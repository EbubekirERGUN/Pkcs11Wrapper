# Pkcs11Wrapper - Guvenlik Kod Incelemesi Raporu

**Tarih:** 2026-04-06  
**Kapsam:** Tum `src/` dizini altindaki C# kaynak kodlari  
**Yontem:** Statik kod analizi (manuel)

---

## Ozet

| Onem | Bulgu Sayisi |
|------|-------------|
| Kritik | 1 |
| Yuksek | 4 |
| Orta | 3 |
| Dusuk | 3 |
| **Toplam** | **11** |

---

## KRITIK Bulgular

### 1. Bootstrap Parolasi Duz Metin Olarak Diske Yaziliyor
- **Dosya:** `src/Pkcs11Wrapper.Admin.Web/Security/LocalAdminUserStore.cs:224-234`
- **Tur:** Hassas Veri Ifsa (CWE-312)
- **Onem:** KRITIK

**Aciklama:**  
Admin bootstrap parolasi `bootstrap-admin.txt` dosyasina duz metin olarak yaziliyor:

```csharp
string bootstrap = $"""
Pkcs11Wrapper Admin bootstrap credential
======================================
username: {userName}
password: {password}
generated_utc: {createdUtc:O}
""";
await CrashSafeFileStore.WriteTextAsync(BootstrapNoticePath, bootstrap, cancellationToken);
```

Dosya disk uzerinde kalici olarak bulunuyor. Dosya sistemi erisimi olan herhangi bir saldirgan parolayi okuyabilir. `File.Delete()` ile silme islemi veriyi diskten geri dondurulmez sekilde silmez.

**Onerilen Duzeltme:**  
- Parolayi yalnizca konsola/stdout'a bir kez yazin, dosyaya kaydetmeyin.
- Dosyaya yazilmasi zorunluysa, dosya izinlerini kisitlayin (600) ve ilk giris sonrasi otomatik silin.
- Guvenli silme icin dosya icerigini rastgele veriyle ustune yazin, sonra silin.

---

## YUKSEK Oncelikli Bulgular

### 2. Zayif Bootstrap Parola Uretimi (GUID Kullanimi)
- **Dosya:** `src/Pkcs11Wrapper.Admin.Web/Security/LocalAdminUserStore.cs:321-325`
- **Tur:** Zayif Rastgele Sayi Uretimi (CWE-338)
- **Onem:** YUKSEK

**Aciklama:**

```csharp
private static string GenerateBootstrapPassword()
    => Convert.ToBase64String(Guid.NewGuid().ToByteArray())
        .Replace("/", "A", StringComparison.Ordinal)
        .Replace("+", "B", StringComparison.Ordinal)
        .Replace("=", "9", StringComparison.Ordinal);
```

`Guid.NewGuid()` kriptografik amaclar icin tasarlanmamistir. Yalnizca 122 bit entropi saglar ve bazi platformlarda tahmin edilebilir olabilir.

**Onerilen Duzeltme:**

```csharp
private static string GenerateBootstrapPassword()
{
    byte[] bytes = RandomNumberGenerator.GetBytes(32);
    return Convert.ToBase64String(bytes)
        .Replace("/", "A", StringComparison.Ordinal)
        .Replace("+", "B", StringComparison.Ordinal)
        .TrimEnd('=');
}
```

---

### 3. PKCS#11 Modul Yolunda Path Traversal Dogrulamasi Eksik
- **Dosya:** `src/Pkcs11Wrapper.Admin.Application/Services/DeviceProfileService.cs:339-353`
- **Tur:** Dizin Gecisi (CWE-22)
- **Onem:** YUKSEK

**Aciklama:**

```csharp
private static string ValidateModulePath(string? value)
{
    string modulePath = value?.Trim() ?? string.Empty;
    if (string.IsNullOrWhiteSpace(modulePath))
        throw new ArgumentException("PKCS#11 module path is required.", nameof(value));
    if (modulePath.Length > 4096)
        throw new ArgumentException("PKCS#11 module path is unexpectedly long.", nameof(value));
    return modulePath;  // Hicbir yol dogrulamasi yok!
}
```

Yalnizca bosluk ve uzunluk kontrolu yapiliyor. `../../../etc/malicious.so` gibi yollar kabul edilir. Saldirgan, keyfi konumlardan PKCS#11 modulu yukletebilir ve potansiyel olarak rastgele kod calistirabilir.

**Onerilen Duzeltme:**

```csharp
private static string ValidateModulePath(string? value)
{
    string modulePath = value?.Trim() ?? string.Empty;
    if (string.IsNullOrWhiteSpace(modulePath))
        throw new ArgumentException("PKCS#11 module path is required.", nameof(value));
    if (modulePath.Length > 4096)
        throw new ArgumentException("PKCS#11 module path is unexpectedly long.", nameof(value));

    string fullPath = Path.GetFullPath(modulePath);
    if (modulePath.Contains("..", StringComparison.Ordinal))
        throw new ArgumentException("PKCS#11 module path contains path traversal sequences.", nameof(value));
    if (!Path.IsPathRooted(fullPath))
        throw new ArgumentException("PKCS#11 module path must be absolute.", nameof(value));

    return fullPath;
}
```

---

### 4. Zayif Cookie Guvenlik Yapilandirmasi
- **Dosya:** `src/Pkcs11Wrapper.Admin.Web/Program.cs:32-42`
- **Tur:** Guvenli Olmayan Yapilandirma (CWE-614, CWE-1004)
- **Onem:** YUKSEK

**Aciklama:**

```csharp
options.Cookie.SameSite = SameSiteMode.Lax;
options.Cookie.SecurePolicy = CookieSecurePolicy.SameAsRequest;
options.SlidingExpiration = true;
options.ExpireTimeSpan = TimeSpan.FromHours(8);
```

| Sorun | Mevcut Deger | Olmasi Gereken |
|-------|-------------|----------------|
| SameSite | Lax | Strict |
| SecurePolicy | SameAsRequest | Always |
| Oturum Suresi | 8 saat | 1-2 saat |
| SlidingExpiration | true | false |

- **SameSite=Lax:** Top-level navigasyonlarda cross-site cookie gonderimini onlemez.
- **SecurePolicy=SameAsRequest:** HTTP uzerinden erisimde cookie sifresiz iletilir.
- **8 saatlik oturum:** Admin paneli icin asiri uzun.
- **SlidingExpiration:** Aktif kullanim devam ettikce oturum surekli uzar, saldiri penceresi genisler.

---

### 5. Open Redirect Zafiyeti
- **Dosya:** `src/Pkcs11Wrapper.Admin.Web/Security/AccountEndpoints.cs:38`
- **Tur:** Dogrulanmamis Yonlendirme (CWE-601)
- **Onem:** YUKSEK

**Aciklama:**

```csharp
return Results.LocalRedirect(string.IsNullOrWhiteSpace(returnUrl) ? "/" : returnUrl);
```

`returnUrl` parametresi form verisinden alinip dogrudan yonlendirme icin kullaniliyor. `Results.LocalRedirect()` mutlak URL'leri engelliyor ancak `//evil.com` veya ozel protokol saldirilarini tamamen onlemedigi senaryolar olabilir.

**Onerilen Duzeltme:**

```csharp
private static bool IsValidReturnUrl(string? url)
{
    if (string.IsNullOrWhiteSpace(url) || !url.StartsWith("/", StringComparison.Ordinal))
        return false;
    return !url.StartsWith("//", StringComparison.Ordinal)
        && !url.Contains("://", StringComparison.Ordinal);
}

// Kullanim:
string safeReturnUrl = IsValidReturnUrl(returnUrl) ? returnUrl : "/";
return Results.LocalRedirect(safeReturnUrl);
```

---

## ORTA Oncelikli Bulgular

### 6. Kullanici Numaralandirma (Timing Attack)
- **Dosya:** `src/Pkcs11Wrapper.Admin.Web/Security/LocalAdminUserStore.cs:30-34`
- **Tur:** Bilgi Ifsa / Zamanlama Saldirisi (CWE-208)
- **Onem:** ORTA

**Aciklama:**  
Var olmayan kullanicilar icin fonksiyon hemen geri donuyor, var olan kullanicilar icin parola hashleme islemi yapiliyor. Yanit suresi farkini olcerek saldirgan gecerli kullanici adlarini tespit edebilir.

**Onerilen Duzeltme:**  
Kullanici bulunamasa bile bir dummy hash dogrulamasi yaparak yanit suresini esitleyin.

---

### 7. HTTPS Yonlendirmesi Yapilandirma ile Devre Disi Birakilabilir
- **Dosya:** `src/Pkcs11Wrapper.Admin.Web/Program.cs:157-160`
- **Tur:** Guvenli Olmayan Varsayilan (CWE-319)
- **Onem:** ORTA

```csharp
if (!runtimeOptions.DisableHttpsRedirection)
{
    app.UseHttpsRedirection();
}
```

HTTPS zorlamasi yapilandirma ile tamamen kapatilabilir. Uretim ortaminda bu secenek kullanildiginda tum trafik sifresiz iletilir.

---

### 8. Content-Security-Policy (CSP) Basligi Eksik
- **Dosya:** `src/Pkcs11Wrapper.Admin.Web/Security/AdminSecurityResponseHeadersExtensions.cs`
- **Tur:** Eksik Guvenlik Basligi (CWE-693)
- **Onem:** ORTA

Diger guvenlik basliklari (X-Frame-Options, X-Content-Type-Options, Referrer-Policy) dogru sekilde uygulanmis ancak CSP basligi yok. Bu, XSS saldiri yuzeyini arttirir.

---

## DUSUK Oncelikli Bulgular

### 9. PIN Maskeleme Ilk ve Son Karakteri Ifsa Ediyor
- **Dosya:** `src/Pkcs11Wrapper.Admin.Infrastructure/ProtectedPinStore.cs:118-119`
- **Tur:** Bilgi Ifsa (CWE-200)

```csharp
private static string Mask(string pin)
    => pin.Length <= 2 ? new string('*', pin.Length)
       : $"{pin[0]}{new string('*', Math.Max(1, pin.Length - 2))}{pin[^1]}";
```

4 haneli "1234" PIN icin maske "1**4" olur ve %50 bilgi ifsa edilir. Brute-force saldirilarini kolaylastirir.

---

### 10. AllowedHosts Joker Karakter
- **Dosyalar:** Tum `appsettings.json` dosyalari
- **Tur:** Host Header Injection (CWE-20)

```json
"AllowedHosts": "*"
```

Tum uygulamalarda joker karakter kullanilmis. Host header injection saldirislarina imkan tanir.

---

### 11. Dosya Islemlerinde TOCTOU Yarisi
- **Dosya:** `src/Pkcs11Wrapper.Admin.Infrastructure/CrashSafeFileStore.cs:100-127`
- **Tur:** Yaris Durumu (CWE-367)

`PromoteTempFile` metodunda `File.Exists()` kontrolu ile `File.Move()` arasi atomik degil. Kod fallback try-catch ile bunu ele aliyor ancak teorik olarak istismar edilebilir.

---

## Olumlu Bulgular

| Alan | Durum |
|------|-------|
| API anahtar hashleme (PBKDF2-SHA256, 100K iterasyon) | Iyi |
| Zamanlama saldirisi korunmasi (`CryptographicOperations.FixedTimeEquals`) | Iyi |
| CSRF korunmasi (Antiforgery token dogrulamasi) | Iyi |
| Rate limiting (kayar pencere, istemci basina partitioning) | Iyi |
| ASP.NET Identity `PasswordHasher` ile parola hashleme | Iyi |
| Request body boyut siniri (1 MB) | Iyi |
| Base64 payload uzunluk dogrulamasi | Iyi |
| Atomik dosya yazimi (write-through + rename) | Iyi |
| PIN degerleri DataProtection API ile sifrelenmesi | Iyi |
| Login throttling (brute-force korunmasi) | Iyi |
| Server header basliginin kaldirilmasi | Iyi |
| Uretim ortaminda hata detaylarinin gizlenmesi | Iyi |
| Guvenlik basliklari (X-Frame-Options, X-Content-Type-Options, Referrer-Policy) | Iyi |
| Rol tabanli erisim kontrolu (Admin, Operator, Viewer) | Iyi |
