---
name: mobile-security-reviewer
description: iOS and Android mobile security review sub-skill
---

# mobile-security-reviewer

Read this when reviewing Android (Java/Kotlin) or iOS (Swift/Objective-C) mobile application source code. Also covers React Native and Flutter where relevant.

## Goal

Find mobile-specific security issues: insecure local data storage, WebView vulnerabilities, exported component abuse, insecure network configuration, certificate pinning gaps, hardcoded secrets, binary protection gaps, and platform-specific injection vulnerabilities.

---

# Part 1: Android Security

## A1. Insecure data storage

### SharedPreferences with sensitive data

`SharedPreferences` stores data as a plaintext XML file on the device filesystem. Any app with root access or a backup can read it.

```java
// Flag: sensitive data in SharedPreferences
SharedPreferences prefs = getSharedPreferences("app_prefs", MODE_PRIVATE);
prefs.edit()
    .putString("auth_token", token)         // Flag: auth token in plaintext
    .putString("user_password", password)   // Flag: password in plaintext
    .putString("credit_card", cardNumber)   // Flag: PII in plaintext
    .apply();

// Safe: use Android Keystore + EncryptedSharedPreferences
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();
SharedPreferences encryptedPrefs = EncryptedSharedPreferences.create(
    context, "secret_prefs", masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
```

**Kotlin:**
```kotlin
// Flag
val prefs = getSharedPreferences("prefs", Context.MODE_PRIVATE)
prefs.edit().putString("session_token", token).apply()

// Safe: use EncryptedSharedPreferences
```

### External storage

`Environment.getExternalStorageDirectory()` and `getExternalFilesDir()` write to locations readable by other apps (before Android 10) or by the user via USB.

```java
// Flag: sensitive data written to external storage
File file = new File(Environment.getExternalStorageDirectory(), "user_data.json");
FileWriter writer = new FileWriter(file);
writer.write(sensitiveJson);

// Safe: use internal storage
File file = new File(context.getFilesDir(), "user_data.json");
```

### SQLiteDatabase with string concatenation

```java
// Flag: SQL injection in SQLite
String query = "SELECT * FROM users WHERE username = '" + username + "'";
db.rawQuery(query, null);

// Safe: use parameterized rawQuery
db.rawQuery("SELECT * FROM users WHERE username = ?", new String[]{username});

// Safe: use ContentValues with standard insert/update
ContentValues values = new ContentValues();
values.put("username", username);
db.insert("users", null, values);
```

---

## A2. WebView vulnerabilities

### addJavascriptInterface

Exposes a Java object to JavaScript. If the WebView loads untrusted content, any page can call arbitrary Java methods via the bridge.

```java
// Flag: addJavascriptInterface exposing sensitive functionality
webView.addJavascriptInterface(new WebAppInterface(this), "Android");

// WebAppInterface has methods callable from any page loaded in the WebView
public class WebAppInterface {
    @JavascriptInterface
    public String getAuthToken() { return tokenManager.getToken(); }  // Flag: exposed to JS
    @JavascriptInterface
    public void executeQuery(String sql) { db.execSQL(sql); }         // Flag: SQLi via JS bridge
}

// Remediation:
// 1. Only load trusted, HTTPS URLs in WebViews that use addJavascriptInterface
// 2. Restrict methods exposed via @JavascriptInterface
// 3. If loading untrusted content, do NOT use addJavascriptInterface — use postMessage instead
```

### loadUrl with user-controlled input

```java
// Flag: user-controlled URL loaded in WebView
String url = getIntent().getStringExtra("url");
webView.loadUrl(url);   // javascript:alert(1) would execute

// Flag: javascript: scheme not filtered
webView.loadUrl(userUrl);  // should filter javascript:, file:, data: schemes

// Safe
if (url.startsWith("https://trusted.example.com")) {
    webView.loadUrl(url);
} else {
    throw new SecurityException("Untrusted URL");
}
```

### JavaScript enabled for non-JS content

```java
// Flag: JavaScript enabled without necessity
WebSettings settings = webView.getSettings();
settings.setJavaScriptEnabled(true);  // only set if JS is actually needed

// Flag: file access enabled
settings.setAllowFileAccess(true);           // allows file:// URIs
settings.setAllowFileAccessFromFileURLs(true); // allows XSF attacks
settings.setAllowUniversalAccessFromFileURLs(true);  // allows access to any origin from file://

// Safe defaults
settings.setAllowFileAccess(false);
settings.setAllowFileAccessFromFileURLs(false);
settings.setAllowUniversalAccessFromFileURLs(false);
```

---

## A3. Exported components without permission checks

Components with `exported="true"` (or no explicit setting when `intent-filter` is present, which implicitly exports them on older API levels) are reachable by other apps.

### AndroidManifest.xml flags

```xml
<!-- Flag: exported Activity with no permission requirement -->
<activity android:name=".AdminActivity"
    android:exported="true" />     <!-- any app can launch this -->

<!-- Flag: exported provider with no permission -->
<provider android:name=".UserDataProvider"
    android:authorities="com.example.provider"
    android:exported="true" />     <!-- any app can query this content provider -->

<!-- Flag: exported BroadcastReceiver with no permission -->
<receiver android:name=".TokenReceiver"
    android:exported="true">
    <intent-filter>
        <action android:name="com.example.TOKEN_REFRESH" />
    </intent-filter>
</receiver>

<!-- Safe: restrict with permission -->
<activity android:name=".AdminActivity"
    android:exported="true"
    android:permission="com.example.ADMIN_PERMISSION" />
```

### Intent spoofing

```java
// Flag: Activity reads sensitive data from Intent without verification
public class PaymentActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        String amount = getIntent().getStringExtra("amount");  // attacker-controlled
        processPayment(amount);  // no validation of caller
    }
}

// Remediation: verify caller with getCallingActivity() or use PendingIntent for trusted flows
```

### Deep link hijacking

```xml
<!-- Flag: deep link with exported activity and no host verification -->
<activity android:name=".DeepLinkActivity" android:exported="true">
    <intent-filter android:autoVerify="false">   <!-- Flag: autoVerify disabled -->
        <action android:name="android.intent.action.VIEW" />
        <data android:scheme="myapp" android:host="*" />  <!-- Flag: wildcard host -->
    </intent-filter>
</activity>
```

```java
// Flag: deep link URI used without validation
Uri uri = getIntent().getData();
String redirectUrl = uri.getQueryParameter("redirect");
webView.loadUrl(redirectUrl);  // open redirect / XSS via deep link
```

---

## A4. allowBackup=true

When `allowBackup=true` (the default before Android 12), `adb backup` can extract app data including databases, SharedPreferences, and files — even without root access.

```xml
<!-- Flag: allowBackup not explicitly set to false -->
<application
    android:label="@string/app_name"
    <!-- android:allowBackup not present — defaults to true on older apps -->
    android:icon="@mipmap/ic_launcher" >

<!-- Also flag: allowBackup="true" for apps storing sensitive data -->
<application android:allowBackup="true" ...>

<!-- Safe -->
<application android:allowBackup="false" ...>
```

---

## A5. Hardcoded API keys in BuildConfig / source

```java
// Flag: hardcoded secrets in source
public static final String API_KEY = "AIzaSyABCDEFGHIJKLMNOP";
private static final String STRIPE_SECRET = "sk_live_abcdef123456";

// Flag: keys in BuildConfig (visible in decompiled APK)
BuildConfig.MAPS_API_KEY      // value baked into classes.dex
BuildConfig.ANALYTICS_KEY

// Flag: keys in string resources (visible in decompiled resources.arsc)
// res/values/strings.xml: <string name="google_maps_key">AIzaSy...</string>
```

**Remediation:** Use Android Keystore for runtime key derivation. Fetch secrets from a secure server at runtime using mutual TLS. Never store live/production API keys in APK resources.

---

## A6. Insecure TrustManager (accepting all certificates)

```java
// Flag: TrustManager that accepts all certificates — disables TLS validation
TrustManager[] trustAllCerts = new TrustManager[] {
    new X509TrustManager() {
        public void checkClientTrusted(X509Certificate[] chain, String authType) {}  // empty
        public void checkServerTrusted(X509Certificate[] chain, String authType) {}  // empty — accepts any cert
        public X509Certificate[] getAcceptedIssuers() { return null; }
    }
};
SSLContext sc = SSLContext.getInstance("SSL");
sc.init(null, trustAllCerts, new java.security.SecureRandom());
HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());

// Flag: hostname verifier that accepts all
HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);  // always true

// Safe: use the default TrustManager — it validates certificates by default
// For certificate pinning, use OkHttp CertificatePinner:
OkHttpClient client = new OkHttpClient.Builder()
    .certificatePinner(new CertificatePinner.Builder()
        .add("api.example.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
        .build())
    .build();
```

---

## A7. Parcelable deserialization vulnerabilities

```java
// Flag: reading Parcelable from untrusted Intent without validation
Bundle extras = getIntent().getExtras();
MyObject obj = extras.getParcelable("data");  // type not verified before Android 13

// On Android pre-13, a malicious app can send a crafted Parcel that deserializes to a
// different type than expected — leading to type confusion or code execution in some cases.

// Remediation: on Android 13+ use the typed getParcelable(key, Class) overload
MyObject obj = extras.getParcelable("data", MyObject.class);

// Validate all fields after deserialization
if (obj == null || !obj.isValid()) { finish(); return; }
```

---

## A8. Root detection bypass awareness

Root detection alone is not a security control, but its absence means a rooted device can read all app data. Flag:

```java
// Flag: root detection absent in high-security apps (banking, healthcare)
// Look for absence of RootBeer, SafetyNet/Play Integrity API checks

// Flag: easily bypassable root checks
boolean isRooted = new File("/system/app/Superuser.apk").exists();
// Easily bypassed by removing the file — no Frida/Magisk detection

// Recommendation: use Google Play Integrity API for attestation
IntegrityTokenProvider integrityTokenProvider = IntegrityManagerFactory
    .create(context)
    .requestIntegrityToken(...);
```

---

## A9. Network security config

```xml
<!-- Flag: cleartext HTTP traffic allowed -->
<!-- AndroidManifest.xml -->
<application android:usesCleartextTraffic="true" ...>

<!-- Flag: network_security_config.xml allowing cleartext or custom CAs without pinning -->
<!-- res/xml/network_security_config.xml -->
<network-security-config>
    <base-config cleartextTrafficPermitted="true">   <!-- Flag -->
        <trust-anchors>
            <certificates src="user" />  <!-- Flag: trusting user-installed CAs -->
        </trust-anchors>
    </base-config>
</network-security-config>

<!-- Safe -->
<network-security-config>
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system" />
        </trust-anchors>
    </base-config>
    <domain-config>
        <domain includeSubdomains="true">api.example.com</domain>
        <pin-set>
            <pin digest="SHA-256">base64encodedpin==</pin>
        </pin-set>
    </domain-config>
</network-security-config>
```

---

# Part 2: iOS Security

## I1. Insecure Keychain access (`kSecAttrAccessibleAlways`)

The Keychain is the correct place for secrets, but the accessibility attribute determines when the item can be accessed.

```swift
// Flag: accessible always — item readable even when device is locked and never backed up is not set
let query: [String: Any] = [
    kSecClass as String: kSecClassGenericPassword,
    kSecAttrAccessible as String: kSecAttrAccessibleAlways,  // Flag: always readable
    kSecValueData as String: tokenData
]
SecItemAdd(query as CFDictionary, nil)

// Flag: accessible after first unlock (common but weaker than WhenUnlockedThisDeviceOnly)
kSecAttrAccessibleAfterFirstUnlock           // readable until reboot after first unlock

// Safe: only accessible when device is unlocked, not backed up to iCloud
kSecAttrAccessibleWhenUnlockedThisDeviceOnly  // recommended for auth tokens
kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly  // strongest: requires passcode
```

**Objective-C:**
```objc
// Flag
NSDictionary *query = @{
    (__bridge id)kSecClass: (__bridge id)kSecClassGenericPassword,
    (__bridge id)kSecAttrAccessible: (__bridge id)kSecAttrAccessibleAlways,
    (__bridge id)kSecValueData: tokenData
};
```

---

## I2. UserDefaults storing sensitive data

`NSUserDefaults` / `UserDefaults` is a plaintext plist file. It is included in iCloud and iTunes backups by default.

```swift
// Flag: sensitive data in UserDefaults
UserDefaults.standard.set(authToken, forKey: "auth_token")
UserDefaults.standard.set(userPassword, forKey: "password")   // Flag: plaintext password
UserDefaults.standard.set(creditCardNumber, forKey: "cc")     // Flag: PCI data

// Safe: use Keychain for sensitive values
let keychain = KeychainSwift()
keychain.set(authToken, forKey: "auth_token")
// Or use SecItemAdd directly with kSecAttrAccessibleWhenUnlockedThisDeviceOnly
```

---

## I3. ATS disabled (NSAllowsArbitraryLoads)

App Transport Security (ATS) enforces HTTPS with TLS 1.2+. Disabling it allows cleartext HTTP traffic.

```xml
<!-- Flag: ATS completely disabled in Info.plist -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSAllowsArbitraryLoads</key>
    <true/>       <!-- Flag: disables ATS for all connections -->
</dict>

<!-- Flag: exceptions for specific domains beyond dev/local -->
<key>NSAppTransportSecurity</key>
<dict>
    <key>NSExceptionDomains</key>
    <dict>
        <key>api.example.com</key>
        <dict>
            <key>NSExceptionAllowsInsecureHTTPLoads</key>
            <true/>   <!-- Flag: HTTP allowed for this domain -->
        </dict>
    </dict>
</dict>

<!-- Safe: no NSAppTransportSecurity key (ATS enabled by default) or domain-specific exceptions with justification -->
```

---

## I4. UIWebView vs WKWebView

`UIWebView` was deprecated in iOS 12 and removed from App Store acceptance in 2020. It has unpatched vulnerabilities and no isolation boundary.

```swift
// Flag: UIWebView usage (deprecated and insecure)
let webView = UIWebView()
webView.loadRequest(URLRequest(url: url))

// Also flag: UIWebView in Objective-C
// UIWebView *webView = [[UIWebView alloc] initWithFrame:frame];

// Safe: use WKWebView with content security policies
let config = WKWebViewConfiguration()
config.preferences.javaScriptEnabled = true  // only if needed
let webView = WKWebView(frame: .zero, configuration: config)

// Flag: WKWebView with JavaScript message handler exposed to untrusted content
config.userContentController.add(self, name: "nativeBridge")
// If untrusted URLs are loaded, the nativeBridge is exposed to attacker-controlled JS
```

---

## I5. Custom URL scheme hijacking

Custom URL schemes (e.g., `myapp://`) can be registered by any app. A malicious app can register the same scheme and intercept deep links, OAuth callbacks, and sensitive parameters.

```swift
// Flag: sensitive data in URL scheme callback
func application(_ app: UIApplication, open url: URL,
                 options: [UIApplication.OpenURLOptionsKey: Any] = [:]) -> Bool {
    // url could be: myapp://oauth?code=secretcode
    let code = url.queryParameters["code"]  // Flag: OAuth code via interceptable scheme
    exchangeCodeForToken(code)
    return true
}

// Flag: no verification of the source app
// options[.sourceApplication] should be checked for sensitive flows

// Remediation:
// Use Universal Links (HTTPS deep links) instead of custom URL schemes for OAuth callbacks
// Verify sourceApplication where possible
// Do not pass sensitive secrets through URL scheme parameters
```

---

## I6. Binary protections

These should be present in a production binary. Flag their absence:

| Protection | How to check (source) | How to verify (binary) |
|-----------|----------------------|----------------------|
| **PIE (Position Independent Executable)** | Not directly visible in source; check Xcode build settings `OTHER_CFLAGS` for `-no-pie` | `otool -hv <binary>` — should show `PIE` flag |
| **Stack canary** | Absence of `-fno-stack-protector` in build flags | `otool -I -v <binary>` — check `___stack_chk_fail` symbol exists |
| **ARC (Automatic Reference Counting)** | Source uses ARC by default; flag: `-fno-objc-arc` in build settings | Presence of `objc_release` / `objc_retain` calls |
| **Bitcode** | Xcode `ENABLE_BITCODE = YES` (less critical, deprecated in Xcode 14) | |
| **Debug symbols stripped** | Release builds: `STRIP_INSTALLED_PRODUCT = YES` in build settings | `nm <binary>` should return no debug symbols |

**Detection in source (build settings/Podfile/project.pbxproj):**
```
# Flag in project.pbxproj
ENABLE_HARDENED_RUNTIME = NO;     // disables runtime memory protections on macOS (also affects iOS extensions)
OTHER_CFLAGS = "-fno-stack-protector";  // disables stack canary
OTHER_CFLAGS = "-no-pie";               // disables ASLR
```

---

## I7. Certificate pinning bypass patterns

```swift
// Flag: URLSession delegate that accepts invalid certificates
class InsecureDelegate: NSObject, URLSessionDelegate {
    func urlSession(_ session: URLSession,
                    didReceive challenge: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        // Flag: accepting any certificate
        let credential = URLCredential(trust: challenge.protectionSpace.serverTrust!)
        completionHandler(.useCredential, credential)  // never do this
    }
}

// Safe: implement pinning
func urlSession(_ session: URLSession,
                didReceive challenge: URLAuthenticationChallenge,
                completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
    guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
          let serverTrust = challenge.protectionSpace.serverTrust else {
        completionHandler(.cancelAuthenticationChallenge, nil)
        return
    }
    // Compare server certificate public key hash to pinned values
    if pinnedPublicKeyMatchesServerTrust(serverTrust) {
        completionHandler(.useCredential, URLCredential(trust: serverTrust))
    } else {
        completionHandler(.cancelAuthenticationChallenge, nil)
    }
}
```

**Objective-C:**
```objc
// Flag: kCFStreamSSLValidatesCertificateChain = kCFBooleanFalse
NSDictionary *settings = @{
    (__bridge id)kCFStreamSSLValidatesCertificateChain: (__bridge id)kCFBooleanFalse
};
// Disables all certificate validation
```

---

## I8. SQL injection via sqlite3_exec / FMDB

```swift
// Flag: string interpolation in SQLite query
let query = "SELECT * FROM users WHERE name = '\(username)'"
sqlite3_exec(db, query, nil, nil, nil)  // Flag: SQLi

// Flag: FMDB with string formatting
db.executeQuery("SELECT * FROM users WHERE id = \(userId)", withArgumentsIn: [])

// Safe: FMDB parameterized query
db.executeQuery("SELECT * FROM users WHERE id = ?", withArgumentsIn: [userId])

// Safe: sqlite3_prepare_v2 with bind
var stmt: OpaquePointer?
sqlite3_prepare_v2(db, "SELECT * FROM users WHERE name = ?", -1, &stmt, nil)
sqlite3_bind_text(stmt, 1, username, -1, SQLITE_TRANSIENT)
```

---

## I9. Insecure local storage (NSCoder, plist, NSUserDefaults)

```swift
// Flag: sensitive object serialized to Documents directory (iCloud backup path)
let docDir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
let fileUrl = docDir.appendingPathComponent("user_data.plist")
NSKeyedArchiver.archiveRootObject(sensitiveObject, toFile: fileUrl.path)  // Flag: unencrypted plist

// Flag: writing sensitive data to .plist in Library/Preferences
// (auto-synced to iCloud if iCloud backup enabled)
let defaults = UserDefaults.standard
defaults.set(sensitiveData, forKey: "user_credentials")

// Safe: exclude from backup
var resourceValues = URLResourceValues()
resourceValues.isExcludedFromBackup = true
try? fileUrl.setResourceValues(resourceValues)

// Safe: use Data Protection with .completeFileProtection
FileManager.default.createFile(
    atPath: filePath, contents: encryptedData,
    attributes: [FileAttributeKey.protectionKey: FileProtectionType.complete]
)
```

---

## I10. Logging sensitive data

```swift
// Flag: sensitive data in logs (visible in device console, crash reports)
print("User token: \(authToken)")
NSLog("Login response: %@", responseBody)  // may contain credentials
os_log("Payment data: %@", cardNumber)    // Flag

// Safe: redact sensitive data from logs
// In production, use os_log with privacy qualifiers
os_log("User logged in: %{private}@", username)  // %{private} redacts in non-debug builds
```

---

## React Native and Flutter notes

**React Native:**
- `AsyncStorage` is unencrypted — same issue as SharedPreferences/NSUserDefaults. Use `react-native-encrypted-storage` or `react-native-keychain`.
- Deep links handled in `Linking.addEventListener` — check for open redirects and injected parameters.
- `WebView` component: check `javaScriptEnabled`, `allowsInlineMediaPlayback`, `mixedContentMode`.

**Flutter:**
- `SharedPreferences` package maps to SharedPreferences (Android) / NSUserDefaults (iOS) — unencrypted.
- `flutter_secure_storage` uses Android Keystore / iOS Keychain — preferred for secrets.
- HTTP package: does not do certificate pinning by default. Use `dart:io` `SecurityContext` for pinning.

---

## Detection checklist

| Check | Android | iOS |
|-------|---------|-----|
| Secrets in persistent storage | SharedPreferences keys like `token`, `password`, `key` | UserDefaults keys like `auth`, `secret`, `pin` |
| Cleartext HTTP | `usesCleartextTraffic="true"` in manifest | `NSAllowsArbitraryLoads` in Info.plist |
| WebView JS exposure | `addJavascriptInterface` | `userContentController.add` with untrusted URLs |
| SQL injection | `rawQuery(query, null)` with string concat | `sqlite3_exec` with string formatting |
| Cert validation disabled | Empty `checkServerTrusted` | `completionHandler(.useCredential, ...)` always |
| Exported components | `exported="true"` in manifest | URL schemes without Universal Links |
| Hardcoded secrets | `API_KEY = "..."` in source/BuildConfig | Hardcoded strings, `plist` API keys |
| Backup enabled | `allowBackup="true"` | Files not excluded from backup |
| Old WebView | N/A | `UIWebView` usage |
| Logging sensitive data | `Log.d(TAG, token)` | `print(token)` / `NSLog` with credentials |

## Output format per finding

```json
{
  "file": "app/src/main/java/com/example/LoginActivity.java",
  "line": 48,
  "platform": "android",
  "vuln_type": "insecure_storage",
  "severity": "high",
  "cwe": "CWE-312",
  "owasp_mobile": "M2:2024 - Inadequate Supply Chain Security",
  "title": "Auth token stored in plaintext SharedPreferences",
  "description": "The authentication token is stored using SharedPreferences with MODE_PRIVATE. This data is readable on rooted devices, via adb backup (if allowBackup=true), or through a malicious app with matching user ID on older OS versions.",
  "remediation": "Replace with EncryptedSharedPreferences using MasterKey with AES256_GCM. Ensure android:allowBackup=false in AndroidManifest.xml."
}
```
