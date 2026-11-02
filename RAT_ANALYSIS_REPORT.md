# Malware Analysis Report — `LWTV` / `com.yunyou.control.dev`

**Sample file:** `LWTV_com.yunyou.control.dev_v274.533.185.apk` (6,158,481 bytes)
**APK SHA-256:** `056a8db666e4f154f9f6d0b7a00aa0703d2990ee2b1a085b7339a49bdef90495`
**Decrypted payload SHA-256:** `cf6153e8e4b78cff0526df2d4580cbb48f816a460ec719808303c4e59927eb12`
**Sample date (zip timestamps):** 2026-11-01
**Package:** `com.yunyou.control.dev`
**App label:** `LWTV`
**versionName:** `274.533.185` (manifest) / payload `0.2.0` (vc68)
**minSdk / targetSdk:** 28 / 34
**Classification:** **Android RAT / Remote-Control ("助控") implant with credential theft, SMS theft, and full accessibility-driven remote control. Actively operated (managed C2 + licensing).**

---

## 1. Executive summary

`LWTV` is not a TV app. It is a heavily hardened, professionally operated **Android Remote Access Trojan** built around Android's **Accessibility Service** API. The distributed APK is only a **packed loader** (26 KB DEX); the real 9.95 MB RAT payload is **AES-GCM encrypted inside `assets/VOUALmvLXIYX`** and loaded **in-memory** at app start via `InMemoryDexClassLoader`, after hijacking the original `Application` class.

Once running it provides an operator with:
- **Live remote screen viewing** (periodic JPEG screenshots + full UI-tree "semantic" dumps)
- **Full touch/gesture/text injection** (tap, swipe, long-press, drag, text replace, open apps)
- **Lock-screen credential theft** — captures PIN / pattern / password, plus a **fake "Identity Verification" biometric prompt**
- **SMS theft** — dumps the entire inbox and pushes new inbound SMS in real time
- **Full installed-app inventory exfiltration** (with icons)
- **Aggressive anti-uninstall / anti-detection** — blocks Settings, app list, accessibility settings, factory reset, and the FGS stop panel; fake OEM system-update / face-scan / fingerprint overlays to hide activity
- **Persistence** — boot/quickboot/user-unlocked/package-replaced receivers, a foreground service with wakelocks, exact alarms, and anti-doze keepalive

C2 is a **managed infrastructure** at `https://www.capebej.com` (a decoy site `https://famelack.com/` is bundled) reached over **HTTPS / WSS (WebSocket) with MQTT5 fallback**, authenticated with a **per-device P-256 key in the Android KeyStore** and a **pinned RSA-2048 server key**. Push-wake uses Firebase (`whh6666-fcm`). An **auto-enrollment grant is hardcoded**, meaning the attacker provisions devices without user action.

**Attribution (see §10):** built by **Chinese-speaking developers** (product branding "云游控制"/Yunyou Control, all operator UI in Simplified Chinese) and **targeted at victims in India** — the implant singles out **UPI/payment apps (Google Pay India, PhonePe, Paytm, BHIM/NPCI, Amazon, WhatsApp)** for credential/OTP theft, captures **SIM PIN/PUK** and lock-screen PIN/pattern, and gates its persistence on **English-locale** devices.

**Real-world impact:** the sample is consistent with a reported case in which a victim's bank account was drained (victim-reported tens of thousands of INR) after the phone displayed a **fake "system update" screen** while the fraud executed in the background — the operator locks the device, opens the banking/UPI app, injects taps, reads the OTP, and transfers funds, all hidden behind the fake update overlay (see §6.6).

**Not implemented:** microphone recording, camera capture, GPS/location, contacts, call-log, clipboard read, shell, WebRTC/VNC. (Remote control is screenshot+accessibility, not live video.)

---

## 2. Distribution container / obfuscation

| Artifact | Size | Notes |
|---|---|---|
| `AndroidManifest.xml` | **56 MB** | Real AXML, padding appended + `fileSize` field set to 56 MB; attribute names/values corrupted to `UNKNOWN_SYSTEM_ATTRIBUTE_*` to break AXML parsers |
| `classes.dex` | 26 KB | Packed loader only — 15 classes |
| `assets/VOUALmvLXIYX` | 4.55 MB | **AES-GCM encrypted RAT payload** (entropy 8.0) |
| `assets/VgvtdgzADdAvZQFnH`, `YVcMZZoMJT`, `uTReZfJJRB` | 0.7–1.7 KB | Additional encrypted blobs |
| 12 random-named top-level files | — | Encrypted resources |
| `lib/*/libdatastore_shared_counter.so` | 5–7 KB | AndroidX DataStore native shim (legitimate component) |

### Loader design (`com.wipjt.payvpkyvn.qczs.wfqq.QBCf3JUtW31HoXBzXWrLzqj9ufczaS extends Application`)

- Real entry class is declared via manifest as `com.yunyou.control.AgentApplication`, but the loader **hijacks `Application`** through `ActivityThread`/`mApplication` reflection (`attachBaseContext`, `onCreate`, `mInitialApplication`).
- Reads `assets/VOUALmvLXIYX`, **AES/GCM/NoPadding** decrypts (`SecretKeySpec`, `GCMParameterSpec`, `Cipher.doFinal`, `updateAAD`), **gunzips**, then loads with **`InMemoryDexClassLoader` / `DexClassLoader`** (never written to disk by itself).
- Key material is recovered at runtime by `recoverKey(String,String)` implemented as a **custom bytecode VM** (8 state-machine classes `Bg9jFLdasuc2OdA … WSkU7JlN8wC0WeKn`, each exposing `v0..v9`) — anti-analysis control-flow virtualization.
- Hardcoded hash/key constants seen as loader strings:
  - `e3be74b947cf6150bf1e43c40aacec32`
  - `892b2ce5499cda8305aeb1cd8442f1ec42279302840def82e90cf4da7b7d1c65`
  - `ae6fc4767f061a61d9d125098b95c4fd1b77b0ecba204fd68544ed53a88830d3`
- DEX header fields (`code_off`, `method_id` indices) are deliberately scrambled (offsets up to ~4.8 billion in a 26 KB file) to break jadx/baksmali/apktool.
- Binary built with R8 8.2.2-dev, `min-api 26`, full mode.

### Manifest anti-analysis
The real capabilities are buried among **999 declared permissions** — the vast majority are **fake/hallucinated** (`com.splm.qwcqu.*`). Of the 999 entries, only **17 are real platform permissions**; the other **982 are fabricated** (strung together from words like `PUSH/HANDLER/MONITOR/PROVIDER/SERVICE/CONTROL/ACCESS` plus a random 6-letter suffix, e.g. `PUSH_PROCESSOR_GSCZBG`, `CACHE_CONTROL_TJVCTR`). None of the fake names are defined anywhere, so they are inert; they exist purely to bloat/confuse the manifest and static scanners.

**Declared permissions: 999 total = 17 real + 982 fake.**

#### The 17 real permissions (all of them)

| Permission | Group | Why it matters for the RAT |
|---|---|---|
| `android.permission.INTERNET` | Network | C2 communication (HTTPS/WSS/MQTT) |
| `android.permission.ACCESS_NETWORK_STATE` | Network | Detect connectivity to trigger reconnect |
| `android.permission.READ_SMS` | SMS | **Dump the entire SMS inbox to C2** |
| `android.permission.RECEIVE_SMS` | SMS | **Intercept inbound SMS in real time (OTP theft)** |
| `android.permission.WRITE_SETTINGS` | System | Modify system settings; mask operator activity |
| `android.permission.RECEIVE_BOOT_COMPLETED` | Startup | **Persistence — auto-start after reboot** |
| `android.permission.FOREGROUND_SERVICE` | Service | Keep the C2 connection alive as a foreground service |
| `android.permission.FOREGROUND_SERVICE_DATA_SYNC` | Service | FGS type for continuous data/sync |
| `android.permission.FOREGROUND_SERVICE_SPECIAL_USE` | Service | FGS type for the persistent control channel |
| `android.permission.USE_EXACT_ALARM` | Scheduling | Exact alarms for keepalive/recovery |
| `android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS` | Power | **Defeat Doze/battery killing to stay resident** |
| `android.permission.WAKE_LOCK` | Power | Hold CPU/Wi-Fi awake for C2 |
| `android.permission.POST_NOTIFICATIONS` | Notifications | Display the (deceptive) foreground-service notification |
| `android.permission.USE_BIOMETRIC` | Biometric | **Fake biometric prompt for credential capture** |
| `android.permission.USE_FINGERPRINT` | Biometric | Legacy biometric API for the same |
| `android.permission.MODIFY_AUDIO_SETTINGS` | Audio | Adjust audio settings (see note — no mic record) |
| `com.google.android.c2dm.permission.RECEIVE` | FCM | **Receive Firebase push-wake (`RECONNECT`)** |

> Notably **absent**: `CAMERA`, `RECORD_AUDIO`, `ACCESS_FINE/COARSE_LOCATION`, `READ_CONTACTS`, `READ_CALL_LOG`, `READ_EXTERNAL_STORAGE`, `SYSTEM_ALERT_WINDOW`, `QUERY_ALL_PACKAGES`. This matches the payload analysis: no camera/mic/GPS/contacts/call-log/shell. Screen access is obtained exclusively through the **Accessibility Service** (which needs no dangerous runtime permission beyond the user enabling it), and file/app enumeration is done via Accessibility + `PackageManager`, not storage permissions.

#### Fabricated permission names (982)
All share the namespace **`com.splm.qwcqu.`** and are not defined by any package — Android stores them but grants nothing. Examples:
`com.splm.qwcqu.PUSH_SERVICE_XFLRUE`, `com.splm.qwcqu.CACHE_CONTROL_TJVCTR`, `com.splm.qwcqu.SYSTEM_SERVICE_BCTAGZ`, `com.splm.qwcqu.FOREGROUND_SERVICE_BEPLNB`, `com.splm.qwcqu.TOKEN_MANAGER_CWJDZR`, `com.splm.qwcqu.MESSAGE_SERVICE_NTRWWL`, … (982 total). Full list in `AndroidManifest.dumpsys-full.txt` and `AndroidManifest.decoded.xml`.

---

## 3. Method of analysis

1. Static: `unzip`, hex/entropy analysis, androguard, jadx, custom DEX parser (confirmed scrambled headers), aapt2 badging.
2. Dynamic (isolated emulator): Android 33 (google_apis, arm64, no Play Store), `frida-server` 17.25.1. The app was launched, the loader self-decrypted the payload, and Frida **scanned process memory for `dex\n039` magic**, recovering the decrypted payload (`9959240` bytes, 1481 real classes).
3. Decompiled payload with jadx (3505 classes) and analyzed C2 + capabilities.

> Artifacts: decrypted payload `/tmp/lwtv_payload/payload_0x7ac6cd2000_9959240.dex`; pcap `/tmp/rea_capture.pcap`; decompiled tree `/tmp/lwtv_payload_src/`.

---

## 4. C2 infrastructure

### Hardcoded values (`com.yunyou.control.BuildConfig`)

| Key | Value |
|---|---|
| **API / C2 base URL** | `https://www.capebej.com` |
| **Decoy/cover site** | `https://famelack.com/` |
| **Pinned server RSA-2048 public key (SPKI)** | `MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAuSuluH2sNhOMvh0VpS29YiY0/lzA3CaJDvi3jpRYowjS3dzKSfhiPNQ97CKzowin8mROeT8faKytXK4KLUYsLE0zGzHqFUUbWg6RcM+AVQ252yJ5CVAt+Q8LtpEW1RFKKhFdunWHdgYKJUiabwzXaZwf8O/J9uknsv+xasWEvQrJueatXEvmlpra88vGZ7kQeYhPYlg8iuFIWBc6GO25SV26UrD+Jsip71Xum6Bqfkn8ikoB8Fzl/rIFk3lDii7d8YcNmF7MtfvnsDvJjrFnkEa1MOQTuLdR9A6XUwTrOmqh+1QaflBzf1wcYlDtNDl/99acL3yz13JUjqLsF4vmQRCEjxqe9QbjqOlvs+WcE2wCMMwz9qPepTjRbF3hwySEdE0OiTUH0Mtr3sruac4+BBoKo4pUZN+eOiyyR172jOzuV8+OVmDi1OOVPfXi1k5JnuIc5o4m4reF31QJKmb8PcMWC4CtuMElNNyzfR23bSPg+mGYRiC1sNpQ4bK8ka0NAgMBAAE=` |
| **FCM project** | `whh6666-fcm` |
| **FCM sender ID** | `149789333529` |
| **FCM application ID** | `1:149789333529:android:c481d56df9b970ef5f7288` |
| **FCM API key** | `AIzaSyAU78JJ5xN5gNrpNwSPk5KbnsrcLzRiuC8` |
| **Auto-enrollment grant** | `JLGBCY2qyEfkqUvqxaa6Mt7hp4buPY77nAZHlkjop2Q` |
| Grant ID / policy | `09e6ba8c-93aa-439d-bbcb-a627c03b612e` / `ACCOUNT_BOUND_V1` |
| Server-bind integrity SHA-256 | `2aa51771a3151e89c7e28a69f0f6c39db409adf8e335d86056af52ea5d9cfb7f` |

### Protocol

- **Endpoint discovery:** `GET https://www.capebej.com/m9eu/00/it2` returns a **signed JWS manifest** with up to 4 `origins` + `preferred_origin` (TTL), which become the live C2 hosts.
- **Transports (one active at a time):**
  - **WebSocket** `wss://{origin}/m9eu/00/d1` (preferred) — plaintext JSON frames over TLS; headers `Authorization: Bearer <access_token>`, `X-Handshake-Seq`.
  - **MQTT5 (Eclipse Paho v5)** fallback via `ssl://host:port`, TLS pinned; topics `yy/v1/device/{username}/session|/up|/down`. Credentials rotated by C2 at `/m9eu/00/3d4`.
- **Obfuscated REST paths** (all under `/m9eu/00/`):
  `it2` manifest · `nm` challenge · `by` enroll submit · `jt` auth submit · `d1` WS · `ss6` FCM token report · `91v` FCM wake ack · `3d4` MQTT creds · `d0` SMS sync · `2vx`/`0v7`/`jj`/`jj/{id}` material & result reporting · `cpa`/`ha`/`d3/dm`/`x1/yd6` app-inventory sync · `kf/<id>/lm` material download.
- **Device identity / auth:**
  - Per-device **P-256 key** in AndroidKeyStore, alias `yunyou.installation.v1`; `SHA256withECDSA` challenge-response.
  - `installation_id` = random UUID in `noBackupFilesDir/installation.json`.
  - Challenge → submit signed → receive `access_token` (max lifetime 900 s, refresh ≤60 s before expiry).
  - Server authenticity verified against the pinned RSA key (`SHA256withRSA`, SPKI match).
  - Command leases are JWS (`iss=yunyou`, `aud=android-device`) fenced by `asset_id`, `installation_id`, `process_run_id`, `connection_generation`, `recovery_epoch`, `lease_pair_id`, `grant_seq`.
- **Encryption:** TLS only (HTTPS/WSS/MQTTS) with pinned server key. **No payload-level encryption** — control messages are plaintext JSON inside TLS.
- **FCM role:** push **wake only** — data message `type=RECONNECT` with `wake_id` UUID (TTL ≤ 86400 s, 300 s clock skew) to revive the agent.

### Timing / keepalive

| Behavior | Value |
|---|---|
| Pulse/maintenance tick | **250 ms** |
| Heartbeat | when last HB ≥ **20 s** |
| Heartbeat ACK timeout | **60 s** → `HEARTBEAT_TIMEOUT` disconnect |
| Independent HB watchdog | every 10 s |
| Endpoint refresh | ~30–60 s (jittered) |
| SMS sync check | ≥ 60 s |
| Reconnect backoff | `Retry-After` on 429/503, clamped 1–86400 s |
| FGS wakelock lease | 120 s |

---

## 5. Command reception — how the RAT gets its orders

The operator never connects to the device. Instead the device **maintains an outbound control channel to the C2** and the C2 pushes commands down that channel. There are three inbound paths; the first is the live control channel, the other two only *wake*/revive it.

### 5.0.1 Primary: persistent WebSocket / MQTT control channel

1. **Connect (outbound).** `DeviceConnection.connect()` → `refreshEndpoint()` fetches the signed endpoint manifest from `GET https://www.capebej.com/m9eu/00/it2`, then `challenge()`/`authenticate()` obtain an `access_token`. It then opens the preferred transport (`openSocket` → OkHttp **WebSocket** to `wss://{origin}/m9eu/00/d1`; fallback `openMqtt` → **MQTT5**). Header: `Authorization: Bearer <access_token>` + `X-Handshake-Seq`.
2. **Receive.** 
   - WebSocket: `DeviceConnection$openSocket$2$2.onMessage(webSocket, text)` is the raw entry (`DeviceConnection$openSocket$2$2.java:36`). Each frame is size-checked (`≤131072` bytes via `InboundMessageBudget`), the JSON parsed, and dispatched on the connection's own `HandlerThread` (`owner` Handler) to **`DeviceConnection.onMessage(JSONObject)`** (`:96-97`).
   - MQTT5: the client subscribes to the downlink topic `yy/v1/device/{username}/down`; `messageArrived()` (`Mqtt5ControlTransport.java:97`) rejects oversized messages (>131072) and anything not on the exact down-topic, then `Mqtt5DownstreamParser.parse()` unwraps the envelope `{"session_id": ..., "message": { "type": ..., "payload": ... }}` and feeds the inner frame to the same `onMessage` handler via the session gate (`:110-112`, `:246`).
3. **Dispatch.** `onMessage(JSONObject)` reads the message's `"type"` field and routes to a per-command handler. The command vocabulary is visible in the class's method table and capability set, e.g. `TAP`, `SWIPE`, `LONG_PRESS`, `DRAG`, `BACK`, `HOME`, `RECENTS`, `SCREEN_ON`, `SCREEN_OFF`, `VOLUME_UP/DOWN`, `MUTE`, `CLIPBOARD_SET`, `OPEN_URL`, `OPEN_APP`, `REOPEN_APP`, `SHOW_KEYGUARD`, `KEYGUARD_UNLOCK`, `SCREEN_OVERLAY`, `DYNAMIC_BLACK_SCREEN`, `NODE_ACTION`, `TEXT_REPLACE`, `FOCUSED_TEXT`, `FOCUSED_PASTE_CAPABILITY`, `SCREENSHOT`, `SEMANTIC`, `PRIVATE_CAPTURE`, `MATERIAL_DOWNLOAD`, `RESTART_AGENT`, `OEM_SETUP_GRANT`, `SETUP_PERMISSION`.
   - Control commands are enforced by an allow-list `readerAllowed` (`DeviceConnection.java:207, 627-640`) = `TAP, SWIPE, LONG_PRESS, BACK, HOME, RECENTS, SCREEN_ON, SCREEN_OFF, VOLUME_UP, VOLUME_DOWN, MUTE, CLIPBOARD_SET, SCREEN_OVERLAY, DYNAMIC_BLACK_SCREEN, OPEN_URL`; anything else must carry a valid **server-signed command lease** (`installGrant` → `Grant`), verified against the pinned RSA key and bound to `asset_id`/`installation_id`/`generation`/`recovery_epoch` (anti-replay fencing).
   - Input commands are queued to the **`LocalInputLane`** and drained on the accessibility reader thread (`drainInputLane`/`runInput`), then executed by `NativeController`.
   - Results are returned via `deliverResults`/`flushResults` → `CommandResultOutbox` (uplink `{"session_id","message":{...}}` over MQTT, or a JSON frame over WS).

### 5.0.2 Wake path: Firebase Cloud Messaging (when the socket is dead)

If the device is asleep / the socket dropped, the C2 sends an **FCM data message** to push the agent back online — it carries **no command**, only a wake signal.
- `FcmWakeService.onMessageReceived()` (`FcmWakeService.java:92`) requires `message.data["wake_id"]` to be a valid UUID and validates TTL/skew/no-notification via `FcmWakeDecision`. On acceptance it calls `KeepaliveRecovery.trigger(...)` which reconnects `DeviceConnection`; the actual command then arrives on the newly opened WS/MQTT channel.
- The FCM token is reported to C2 at `POST /m9eu/00/ss6` so the operator knows where to push.

### 5.0.3 Bootstrap / persistence triggers (re-establish the channel)

Nothing is pushed here; these just start the agent so it can reconnect:
- `LifecycleReceiver`: `BOOT_COMPLETED`, `QUICKBOOT_POWERON`, `USER_UNLOCKED`, `MY_PACKAGE_REPLACED`.
- `SmsReceiver`: `SMS_RECEIVED` (also triggers an immediate `requestSmsSync()` — i.e. new SMS is pushed up on arrival).
- `ConnectionForegroundService` `pulse()` loop (every 250 ms) keeps the channel alive / reconnects.

### 5.0.4 Message shape (examples)

- WebSocket downlink frame (plaintext JSON over TLS): `{"type":"<COMMAND>","payload":{...}}` (or the framed `{"session_id","message":{...}}`).
- MQTT downlink envelope: `{"session_id":"<id>","message":{"type":"<...>","payload":{...}}}`; session control frames use `type` ∈ `SESSION_READY | SESSION_LOST | SESSION_REJECT`.
- Uplink (device→C2): `{"session_id":"<id>","message":{...}}` on `yy/v1/device/{username}/up`; session open publishes `{"session_id","token","handshake_seq"}`.

> **Summary:** commands arrive **over an always-on, device-initiated TLS channel** (WebSocket, or MQTT5 fallback), authenticated by a per-device ECDSA key + `access_token`, with sensitive commands additionally gated by a **server-signed lease**. FCM is used **only as a wake beacon** to revive a dead channel; there is no operator inbound connection, no remote shell, and no listener port on the device.

---

## 6. Capabilities (payload `com.yunyou.control`)

### 6.1 Remote control
- **Screen viewing:** PIXEL mode = periodic **JPEG screenshots** via AccessibilityService `takeScreenshot` (`NativeController.capture`, max 2 MB/frame); SEMANTIC mode = **full UI-tree dump** (`AndroidTreeSampler`/`AndroidTreeRead`); DUAL = both. Not WebRTC (`WEBRTC=false`).
- **Input injection** (`NativeController.execute`): `TAP`, `SWIPE`, `LONG_PRESS`, `DRAG` via `dispatchGesture`; `TEXT_REPLACE`, `NODE_ACTION` (CLICK/LONG_CLICK/SCROLL_FORWARD/SCROLL_BACKWARD), `FOCUSED_TEXT`, `FOCUSED_PASTE_CAPABILITY`.
- **Device/system controls:** `SCREEN_ON/OFF`, `BACK`, `HOME`, `RECENTS`, `VOLUME_UP/DOWN`, `MUTE`, `CLIPBOARD_SET`, `OPEN_URL`, `OPEN_APP`, `REOPEN_APP`, `SHOW_KEYGUARD`, `KEYGUARD_UNLOCK`, `SCREEN_OVERLAY`, `DYNAMIC_BLACK_SCREEN`, `RESTART_AGENT`.

### 6.2 Credential theft (headline)
- **`MaskedFieldExtractor`** captures lock-screen **PIN, pattern, and password** across ~40 OEM keyguard packages and submits `"pin"/"password"/"apppwd"` to `CachedPropertyIndex` (persisted in SharedPreferences `ic_store`).
- **`CredentialCaptureSession`** reconstructs PIN/pattern/password on the lock screen (dot-tracking + digit buffers), with motion-event hijack on API 34+.
- **`CredentialCaptureActivity`** presents a fake **"Identity Verification"** biometric/device-credential prompt.
- **`KeyguardUnlock`/`PinReplay`** replays captured secrets to unlock the device remotely (`PIN_REPLAY_COMPLETED`).
- **`GPaySniffer`** narrows accessibility scope around payment apps (GPay, PhonePe, Paytm, NPCI UPI, Amazon, WhatsApp) to act as a **payment-app keylogger/sniffer** while avoiding detection.

### 6.3 Data theft
- **SMS:** full inbox query `content://sms` (`SmsInitialSync`), paginated upload; live push on `SMS_RECEIVED` (`SmsReceiver`) → `/m9eu/00/d0`.
- **App inventory:** enumerates all launcher apps + icons, exfiltrated (`AppInventoryCapture`/`AppInventorySync`).
- **Device profile:** manufacturer, brand, model, API level, build fingerprint, locales (`PermissionReport`).
- **NOT present:** mic, camera, GPS/location, contacts, call log, clipboard read, file-system browsing, shell.

### 6.4 Persistence
- **Receivers:** `LifecycleReceiver` (`BOOT_COMPLETED`, `QUICKBOOT_POWERON`, `USER_UNLOCKED`, `MY_PACKAGE_REPLACED`), `AntiDozeReceiver`, `KeepaliveRecoveryAlarm`, `FcmWakeService`.
- **Foreground service** `ConnectionForegroundService` with CPU `WakeLock` + `WifiLock`, exact alarms, anti-doze keepalive alarms (`keepalive_alarm_plan.xml` written at runtime).
- **Accessibility pull-up watchdog** re-spawns on death.
- **Auto-enrollment** with the hardcoded grant — no user interaction required to bind to the operator's account.

### 6.5 Anti-detection / evasion
- **`AppProtector`** blocks the user from: app Settings page, app list, accessibility settings, developer settings, and factory reset; hijacks back/home; blocks danger buttons (`Force stop`, `Uninstall`, `Disable`, `Clear data`, `Factory reset`) in ~20 languages; dismisses the FGS stop panel.
- **`DynamicBlackScreen`** — fake full-screen overlays mimicking OEM UIs (`system_update`, `face_scan`, `fingerprint`, Samsung/Huawei-styled, localized) + brightness dimming to **mask operator activity**; hidden during screen grabs (`hideForCapture`).
- **`SetupOverlay`/`SystemThemeOverlay`** — fake system setup screens to coerce the user into granting accessibility.
- **`StopAssistanceReceiver`** refuses to stop while `AppProtector` is active.
- Opaque C2 URL segments instead of named endpoints.

### 6.6 The "fake system update" cover (how the theft actually looks to the victim)

This is the **primary social-engineering cover** and matches observed real-world fraud cases where the victim's phone shows a convincing "system update" screen while money is moved in the background. Two overlay systems cooperate, both driven from `DeviceConnection.onMessage` on C2 command:

1. **`DynamicBlackScreen` — fake update / biometric screen (`SCREEN_OVERLAY`).**
   - Creates a **fullscreen system-level overlay** via `WindowManager` (`LayoutParams(-1, -1, 2032, 792, -3)`, i.e. a `TYPE_SYSTEM_*` window above normal apps), and **dims system brightness to 2–8%** (`layoutParams.screenBrightness = 0.02f/0.05f/0.08f`) so the screen looks like a real "update in progress" dim.
   - Modes: `system_update` (progress-bar "installing…"), `face_scan`, and `fingerprint`. It renders a **progress animation** ("Installing system update…", "Do not turn off your device…"), and in fingerprint mode **actively listens to the fingerprint sensor** (`startFingerprintListening`) to harvest biometric touches.
   - `transitionToSystemUpdate()` chains states: fake **fingerprint prompt → "installing update"**, so the victim cooperates with the "verification" and then just waits, believing the phone is updating.
   - Text is **localized in ~20 languages** and styled to the device's own OEM brand. Crucially, it calls `hideForCapture()` / `restoreAfterCapture()` so **any screenshot or the RAT's own "pixel" capture never shows the fake screen** — the overlay only exists for the human looking at the phone.
   - Being a **system-type window**, it sits over everything and the victim cannot easily see or dismiss the app operating underneath.

2. **`InjectOverlayManager` — per-app WebView page injection (`SCREEN_OVERLAY` / node rules).**
   - Attaches a **fullscreen `WebView` overlay** (again a system window) that loads an **operator-supplied template URL** (validated against a `trustedTemplateUrl` allow-list) and injects **fake forms/pages over specific target apps** (`targetPkg`, per-package `screenRuleList`). It tracks `submittedPkgs`/`cancelledPkgs` and only shows pages the C2 authorizes for that package.
   - Used to present fake login / payment / KYC / credential screens **on top of the real banking, UPI, or Settings app**, so the victim types credentials into the attacker's form while believing it is the genuine app.

**Effect for the victim:** the phone appears to be performing a routine "system update" (or a fingerprint/face verification), while the RAT simultaneously:
- unlocks the device by **replaying the captured PIN/pattern** (`KEYGUARD_UNLOCK` → `PIN_REPLAY`),
- opens the banking/UPI app (`OPEN_APP`), drives it with injected taps/gestures (`TAP`/`SWIPE`/`TEXT_REPLACE`),
- reads and forwards **SMS/OTP** (`SMS_RECEIVED` → `/m9eu/00/d0`),
- and exfiltrates the screen (`PIXEL`/`SEMANTIC`) to the operator in real time.

> This is consistent with a reported real-world case in which a large sum (victim-reported in the tens of thousands of INR) was drained from a victim's bank account while the phone displayed a fake update screen and the operations ran in the background/unattended.

### 5.6 Operator intent (hardcoded Chinese UI strings)
- `"无障碍已连接，正在自动连接"` ("Accessibility connected, auto-connecting")
- `"已停止协助，请在首页明确恢复"` ("Assistance stopped, explicitly resume on home page")
- `"安装包未配置自动登记，请安装管理员提供的 APK"` ("Package not configured for auto-enrollment; install the APK provided by the **administrator**")
- `"自动登记名额已用完，等待管理员更新 APK"` ("Auto-enrollment quota exhausted; wait for the administrator to update the APK")

This is a **managed "assistance/control" (助控) product** run by an "administrator" — i.e., a commercial RAT-for-hire/stalkerware-style service, not a generic banking trojan.

---

## 7. What makes this sample special (distinctive engineering)

This is not a generic Android RAT. Several subsystems are unusually sophisticated and set it apart from common banking trojans / repackaged rats:

1. **Full lock-screen credential reconstruction (not just keystroke logging).** `CredentialCaptureSession` + `KeyguardGrid`/`GestureGridView`/`GridSampleTracker`/`KeyguardScreenKeeper` **reconstruct the lock-screen PIN and swipe **pattern geometrically** — tracking touched dots (`touchedDots`/`touchedDotPoints`), digit buffers (`digitBuffer`/`digitPoints`), and pattern bounds — then **replay it** to unlock. `KeyguardUnlock*` (13 classes) drives `dispatchGesture` to swipe-up and re-enter the captured secret. `KeyguardPinLayoutPolicy`/`KeyguardPinEditorMetadata` handle the varying PIN-keypad layouts across OEMs. This is a purpose-built **keyguard-bypass engine**, rare at this fidelity.

2. **Fake OEM "system update / fingerprint / face" overlay, localized in ~20 languages.** `DynamicBlackScreen` renders pixel-accurate fake system dialogs (`system_update`, face/fingerprint verification) that **impersonate the device's own brand** — it carries brand strings for `Samsung, Xiaomi, Redmi, POCO, HUAWEI, HONOR, OPPO, vivo, realme, OnePlus, Motorola, Nokia, Infinix, Tecno, itel, ASUS, Lenovo, MEIZU, Nothing, Google` and full localized text in **English, French, Spanish, German, Portuguese, Turkish, Russian, Arabic, Hindi, Vietnamese, Indonesian, Malay, Filipino**, etc. It dims the screen, hides itself from screen-captures, and **harvests the biometric/PIN the victim enters into the fake prompt**.

3. **The imposter is a "remote-assistance" product, not a clunky trojan.** A **UI-tree "semantic" streaming mode** (`UiSemantics`, `BackgroundSemantic*`, `SemanticFrame*`) serializes the live accessibility hierarchy into a compact wire format (anchors/rules/levels) and uploads it, *in addition to* JPEG "pixel" frames — so the operator can drive the device by **UI-element semantics** rather than raw coordinates. `PixelAdaptiveController`/`PixelFrameDedup`/`PixelEncodingProfile` adaptively size/dedupe screen frames to the link. `LiveCoordinateInput` (`LIVE_COORDINATE_V1`) and `InjectOverlayManager` support **real-time coordinate injection with display-geometry validation** (expected-vs-live display, screen on/locked checks).

4. **Operator-grade anti-removal ("AppProtector").** Rather than a simple block, it runs a **localized, resource-ID-aware** defense that recognizes and neutralizes the *actual* layout of ~20 OEM Settings/App-info/accessibility/factory-reset screens (danger buttons `Force stop`, `Uninstall`, `Disable`, `Clear data`, `Factory reset` in many languages) and **dismisses the FGS stop panel**. `StopAssistanceReceiver` refuses to stop while protection is on.

5. **Fenced, replay-proof command authoring.** Every sensitive command carries a **server-signed JWS lease** bound to `asset_id`/`installation_id`/`process_run_id`/`connection_generation`/`recovery_epoch`/`lease_pair_id`/`grant_seq` — anti-replay fencing with a **connection-generation and recovery-epoch** model (`ConnectionRetirementPool`, `AgentRestart*`). This is unusually rigorous for Android malware; it prevents captured/replayed C2 traffic from driving the device.

6. **Enrollment-as-a-service licensing.** The APK ships a **hardcoded grant** with an `ACCOUNT_BOUND_V1` policy and per-deployment "quota" enforcement (`AutomaticEnrollment`, `EnrollmentPolicy`) — i.e. the malware is a **resold product with seat licensing**; the operator updates the APK when a customer's seats/credential expire.

7. **Deep keepalive/recovery state machine.** ~30 `Keepalive*` classes plus `AntiDozeReceiver`, `AgentRestartCoordinator`, `ConnectionRetirementPool`, watchdogs, and exact-alarm plans form a resilience layer far beyond a typical FGS — designed to **survive Doze, OEM killers, screen-off, and self-restart** while maintaining the C2 channel.

8. **Persistence automation that "drives" the OEM UI.** `OemAutoReporter`/`OemAutomationBlock`/`SamsungSetup*`/`OemColorOs*`/`OemCommonAppPlan` **navigate the specific Settings pages** (auto-start, background-data, battery-unrestricted) on Xiaomi/OPPO/OnePlus/vivo/Samsung etc., using per-OEM, per-locale menus, to **silently grant itself auto-start and battery exemptions** — English path for India, Chinese path for CN.

9. **Notable non-features.** There is **no anti-RE/anti-Frida/anti-emulator/root-detection** code in the payload (the protection is in the *packer/manifest*, not runtime). No camera, microphone, GPS, contacts, or call-log — the product is a **screen-control + credential/OTP-theft** tool, not a general data harvester.

> Net: the combination of **(a) geometric PIN/pattern reconstruction, (b) ~20-language fake-system-update biometric phishing, (c) semantic UI streaming, (d) signed lease fencing, and (e) licensed enrollment** makes this a **professional, commercially-operated 助控/remote-control product** — well above commodity Android RATs.

---

## 8. Network observations (dynamic run)

- App launch persisted a `keepalive_alarm_plan.xml` and participated in a patched launcher flow (no clean launcher activity; started via `HomeActivity`).
- In the sandbox, only **Google/emulator traffic** (DNS to `android.apis.google.com`, `fonts.gstatic.com`, GCM/etc.) plus localhost sockets (`:27042` = Frida, `:34193/42719/37771` = internal) were observed within the capture window — **no live `capebej.com` connection** because the sandbox environment (Android 33 google_apis, no Play Services enrollment, blockable outbound) did not complete the FCM wake / enrollment handshake in-window.
- TLS pinning + signed manifests mean the C2 endpoints rotate; the bootstrap is `capebej.com`.

---

## 9. Indicators of Compromise

**Files / hashes**
- APK: `LWTV_com.yunyou.control.dev_v274.533.185.apk` — `056a8db666e4f154f9f6d0b7a00aa0703d2990ee2b1a085b7339a49bdef90495`
- Encrypted payload asset: `assets/VOUALmvLXIYX` (4,549,938 bytes) — `49c15345d5df2f97e2b1272fe759da554723bafef84e1e7c8a6b7115453f687e`
- Decrypted payload DEX — `cf6153e8e4b78cff0526df2d4580cbb48f816a460ec719808303c4e59927eb12`

**Network**
- `https://www.capebej.com` (C2 base) — paths `/m9eu/00/*`
- `wss://{origin}/m9eu/00/d1`
- `https://famelack.com/` (decoy)
- Firebase project `whh6666-fcm`, sender `149789333529`
- MQTT topics `yy/v1/device/{username}/session|/up|/down`

### 9.1 Attacker infrastructure (IPs)

> **Important:** the APK contains **no hardcoded IP addresses** — only the domain `www.capebej.com`. The C2 resolves endpoint *origins* at runtime from a signed manifest (`/m9eu/00/it2`), so the actual server IPs can and do rotate. The IPs below are the live resolution of the embedded hostnames at analysis time and are for blocking/threat-intel reference, not fixed indicators.

| Host | Resolved IP(s) | Role | Notes |
|---|---|---|---|
| `www.capebej.com` / `capebej.com` | **`213.111.157.6`** | **C2 base (primary)** | Not behind Cloudflare at the A record; `Trunk-Networks-SG`, ASN **AS43180 (Trunk Networks LTD)**, country SG, account address Seychelles. Abuse: `abuse@trunk-networks.net` |
| `famelack.com` | `104.21.10.11`, `172.67.161.230` | Decoy/cover site | Cloudflare-fronted (real IP hidden). Registered 2025-12-11 via Porkbun |

**Domain registration**
- `capebej.com` — registrar **Cloudflare, Inc.**; created **2026-08-26** (≈1 week before the sample was built), expires 2027-08-26; NS `dante/vita.ns.cloudflare.com`. Very recent registration + the C2 host resolving *off*-Cloudflare to a Seychelles/Singapore VPS is characteristic of short-lived, disposable C2 infrastructure.
- `famelack.com` — registrar **Porkbun LLC**; created 2025-12-11; NS Cloudflare. Used as a benign-looking decoy.

**Attribution caveats**
- The IP `213.111.157.6` is a hosted VPS in a bullet-proof-prone range (Trunk Networks, Seychelles-registered); it is **not** a residential/operator IP and may be replaced at any time.
- Because endpoints rotate via the signed manifest, blocking the current IP will only temporarily disrupt the implant. Blocking the **domains** (`capebej.com`, `famelack.com`) and the **FCM sender/project** is more durable.

**Recommended blocking (network/perimeter)**
```
213.111.157.6
www.capebej.com
capebej.com
famelack.com
```
(Firebase project `whh6666-fcm` / sender `149789333529` should be blocked at the FCM/enterprise policy level.)

**On-device**
- Package `com.yunyou.control.dev`, label `LWTV`
- Accessibility service `com.yunyou.control.AssistanceAccessibilityService`
- Files: `noBackupFilesDir/installation.json`, `noBackupFilesDir/fcm-token`, `shared_prefs/keepalive_alarm_plan.xml`, `shared_prefs/ic_store.xml`
- AndroidKeyStore alias `yunyou.installation.v1`

**Code artifacts**
- Loader package `com.wipjt.payvpkyvn.qczs.wfqq`
- Payload package `com.yunyou.control`

---

## 10. Attribution — Chinese developers, India-targeted

> **Assessment: the implant is built by Chinese-speaking developers and deployed against victims in India.** Confidence: **high** for "China-built" (branding + UI language) and **high** for "India-targeted" (payment-app/keyboard/locale targeting + deployment geometry). The operator console/UI is Chinese (product "云游控制"); the victim side is Indian (UPI/payment apps, English-locale devices, Indian SIM handling) — a classic **China-based developer → India victim** remote-control/stalkerware deployment.

### 10.0 Why India is the target (operator claim corroborated by code)

- **UPI / Indian payment apps are singled out by name** (`GPaySniffer.java:31,76`): `com.google.android.apps.nbu.paisa.user` (**Google Pay India**), `com.google.android.apps.nbu.india.prod`, `com.phonepe.app` (**PhonePe**), `net.one97.paytm` (**Paytm**), `in.org.npci.upiapp` (**BHIM / NPCI UPI**), plus Amazon-India and WhatsApp. The sniffer dynamically hides its accessibility scope around exactly these apps to **harvest UPI/payment credentials and OTPs without being seen**.
- **Indian SIM handling:** SIM **PIN/PUK** entry capture (`SimPin`/`SimPuk`, `sim_pin_entry`, `keyguard_sim_pin_view`/`keyguard_sim_puk_view`, `com.android.systemui:id/simPinEntry`) — Indian carriers commonly enforce a default SIM PIN, so stealing it yields call/SMS control.
- **English-locale victim gating:** the auto-start/persistence automation key off `english(p)` (`OemPageIdentity.java:19` → `Locale...getLanguage() == "en"`) and ships **English + Chinese language packs** (`OemCommonAppPlan`: `englishDataMenus`/`chineseDataMenus`). It is engineered to run on the **English-language Android devices** that dominate the Indian market (while still supporting Chinese).
- **SMS/OTP theft** (`READ_SMS`/`RECEIVE_SMS`, ``SmsInitialSync``) + **lock-screen PIN/pattern capture** — the standard India toolkit for **banking/UPI fraud** (wash the OTP + unlock the device + replay the UPI PIN).
- **Device/OEM mix:** India's market is dominated by Xiaomi, Samsung, vivo, OPPO/realme, Motorola — exactly the OEM set the sample enumerates for auto-start persistence.

### 10.0.1 China-side developer footprints

- **Product/branding is Chinese:** `云游控制` ("Yunyou Control"); all operator strings are Simplified Chinese (enrollment/licensing UX references `管理员` — "administrator"). Bilingual dev string `"\n开发测试设备 / DEV TEST DEVICE\n"`.
- **Package/naming:** `com.yunyou.control` (pinyin `yunyou`), loader namespace `com.wipjt.payvpkyvn.qczs.wfqq`, FCM project `whh6666-fcm`.
- **UI/console language = Chinese, victim facing = English/UPI.** The asymmetry (Chinese operator product pointed at Indian victims) is itself the attribution signal.

> **Confidence note:** the linguistic/branding evidence (Chinese product) and the targeting evidence (India) are both strong and mutually consistent. A specific named group is **not** established; attribute by infrastructure (`capebej.com`/`famelack.com`, FCM `whh6666-fcm`) and TTPs.

### 10.1 Language evidence (Simplified Chinese)


All operator-facing strings are **Simplified Chinese** (with English glosses appended by the authors), e.g.:

```
云游控制 · 设备处理提醒                     "yunyou control · device handling notice"
云游控制提醒 ·                              "yunyou control reminder ·"
正在重启云游控制 / Restarting agent
安装包未配置自动登记，请安装管理员提供的 APK   "package not configured for auto-enrollment;
                                             install the APK provided by the administrator"
自动登记名额已用完，等待管理员更新 APK         "enrollment capacity reached; wait for the
                                             administrator to update the APK"
自动登记凭据已过期/已撤销，等待管理员更新 APK   "enrollment grant expired/revoked; update required"
正在自动登记设备 / Enrolling automatically
停止协助 / Stop assistance
```

- **"云游控制" (Yunyou Control)** is the product name; `yunyou`/云游 is a pinyin-derived brand also seen in the package name `com.yunyou.control`.
- The **"管理员" (administrator)** enrollment/licensing model, the "停止协助" (stop-assistance) UX, and the 助控 framing are typical of the **Chinese commercial remote-assistance / 助控 grayware** ecosystem.
- The build also carries a developer string `"\n开发测试设备 / DEV TEST DEVICE\n"` — intentional CN+EN bilingual labels (the authors translated their own UI).

### 10.2 OEM persistence targeting (China-market + India-market overlap)

- The app explicitly **queries and manipulates the auto-start / power / permission managers of essentially every major OEM** — the same Chinese-brand OEMs that also dominate the Indian market:
  - **Xiaomi/MIUI** (`com.miui.securitycenter`, `com.miui.permcenter.autostart…`, `com.miui.powerkeeper`),
  - **OPPO/realme/OnePlus** (`com.coloros.safecenter`, `com.oplus.safecenter`, `com.oplus.startupapp…`, `com.oneplus.security`),
  - **vivo/iQOO** (`com.iqoo.secure…`),
  - **Huawei / HONOR** (`com.huawei.systemmanager`, `com.hihonor.systemmanager`, `com.honor.permissioncontroller`),
  - **Samsung** (dedicated `SamsungSetup*` automation), plus Meizu, Smartisan, Letv, ASUS, Transsion (itel/Tecno), Lenovo, Motorola, ZTE.
- Accessibility/anti-kill handling enumerates these OEM packages to keep itself alive and to hide from the vendor's security centers. The set covers both the **Chinese** and **Indian** device markets; combined with the UPI/payment and English-locale targeting (§10.0), the primary victim market is **India**.
- A separate **Japanese** UI pack (~22 kana strings) also ships, showing the product is resold across East-Asian/other markets — but the India-specific payment/SIM/UPI logic is the strongest market signal.

### 10.3 Code / build fingerprints

- Package `com.yunyou.control`, loader namespace `com.wipjt.payvpkyvn.qczs.wfqq` (pinyin-derived base `wipjt`), FCM project `whh6666-fcm` (digit-letter handle), branding `云游控制`.
- Kotlin + coroutines + OkHttp + Paho MQTT5 + Firebase — modern, competent engineering (not a low-skill copy-paste sample).

### 10.4 Counter-evidence / caveats (why this is not a firm attribution)

- **Infrastructure is deliberately offshore/neutral**, not Chinese: C2 `www.capebej.com` → `213.111.157.6` (Trunk Networks, ASN 43180, Seychelles-registered, SG range); decoy `famelack.com` (Porkbun + Cloudflare). Both domains Cloudflare-registered.
- **No China-only artifacts**: no Baidu/Qihoo/Tencent/Alipay SDKs, no CN-only C2 domains, no non-Unicode (GBK) encodings that would uniquely localize the authors.
- Chinese strings are widely reused/copied; they may reflect the **contractor/operator locale** rather than the code authors' nationality.
- The product model (administrator-provisioned, account-bound enrollment, per-deployment APK) is a **resellable commercial service**; RAT/stalkerware tooling of this style is redistributed across regions.

### 10.5 Assessment

| Claim | Confidence |
|---|---|
| Chinese-language malware product (CN UI, CN brand "云游控制") | **High** |
| Built/operated by Chinese-speaking developers | **High** |
| **Targets India** (UPI/payment apps, English-locale, Indian SIM handling) | **High** |
| Specific group / nation-state attribution | **Not established** |

**Verdict:** a **China-developed, India-targeted** commercial remote-control / 助控 RAT ("云游控制"/Yunyou Control). The operator product is Chinese; the victim toolkit is tailored to India — **UPI/banking credential & OTP theft** (Google Pay India, PhonePe, Paytm, BHIM/NPCI, Amazon, WhatsApp), SMS/OTP capture, lock-screen PIN/pattern and SIM PIN/PUK theft, and persistence on the Indian-market OEM mix. Attribute by **infrastructure (`capebej.com` / `famelack.com` / FCM `whh6666-fcm`) and TTPs**, not language alone.

---

## 11. Conclusion & recommendations

**Verdict:** Confirmed, actively-operated **Android RAT** ("yunyou.control" / 助控), **built by Chinese-speaking developers and deployed against victims in India** (§10). It provides remote screen control, accessibility keylogging, lock-screen credential theft (PIN/pattern/password + fake biometric prompt), **UPI/banking credential & OTP theft** targeting Google Pay India / PhonePe / Paytm / BHIM-NPCI / Amazon / WhatsApp, **SIM PIN/PUK capture**, SMS theft, app-inventory exfil, hardcoded auto-enrollment, and aggressive anti-uninstall/anti-detection. C2 at `capebej.com` over pinned TLS with WebSocket + MQTT5 fallback and FCM wake. No camera/mic/GPS/contacts/call-log/shell/WebRTC.

**If found on a device (India campaign — prioritise financial/PII response):**
1. Treat the device as fully compromised — **factory reset** is the only trustworthy remediation (the app actively blocks uninstall and reset through its accessibility hook).
2. **Immediately revoke/secure banking and UPI first:** change online-banking and UPI passwords, reset/regenerate the UPI PIN in the bank app, and re-verify registered devices — assume UPI credentials and OTPs were exposed.
3. Rotate all passwords entered on the device (email, WhatsApp, Google, social) and any saved credentials.
4. Change the device's screen-lock PIN/pattern and the **SIM PIN/PUK** (contact the carrier); re-bind biometrics.
5. Notify SMS/OTP-dependent services; assume **all inbound SMS (including bank OTPs) leaked**.
6. Block `capebej.com`, `famelack.com`, `213.111.157.6`, and FCM project `whh6666-fcm` at the network perimeter.
7. Report the sample/hashes to your IR/AV vendor, Google Play Protect, and — for Indian victims — the relevant CERT-In / bank fraud channel.

**Reproduction commands**
```bash
shasum -a 256 LWTV_com.yunyou.control.dev_v274.533.185.apk
shasum -a 256 /tmp/lwtv_payload/payload_0x7ac6cd2000_9959240.dex
```

---

## Appendix A — Full declared permission list (999)


### Real platform permissions (17)

```
android.permission.INTERNET
android.permission.MODIFY_AUDIO_SETTINGS
android.permission.ACCESS_NETWORK_STATE
android.permission.FOREGROUND_SERVICE
android.permission.FOREGROUND_SERVICE_SPECIAL_USE
android.permission.FOREGROUND_SERVICE_DATA_SYNC
android.permission.WAKE_LOCK
android.permission.USE_EXACT_ALARM
android.permission.RECEIVE_BOOT_COMPLETED
android.permission.POST_NOTIFICATIONS
android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS
android.permission.READ_SMS
android.permission.RECEIVE_SMS
android.permission.USE_FINGERPRINT
android.permission.USE_BIOMETRIC
android.permission.WRITE_SETTINGS
com.google.android.c2dm.permission.RECEIVE
```

### Fabricated permissions (982, namespace `com.splm.qwcqu.`)

```
com.splm.qwcqu.PUSH_PROCESSOR_GSCZBG
com.splm.qwcqu.ANALYTICS_HANDLER_YZSKUC
com.splm.qwcqu.WORK_MANAGER_RAGYDO
com.splm.qwcqu.CACHE_CONTROL_TJVCTR
com.splm.qwcqu.SYSTEM_SERVICE_BCTAGZ
com.splm.qwcqu.MOTION_MANAGER_TQOQLM
com.splm.qwcqu.PUSH_SERVICE_XFLRUE
com.splm.qwcqu.FILE_ACCESS_ZWJEPV
com.splm.qwcqu.FOREGROUND_SERVICE_BEPLNB
com.splm.qwcqu.CONTENT_ACCESS_JIUNUI
com.splm.qwcqu.SCHEDULED_ACCESS_UNIBJQ
com.splm.qwcqu.TELEPHONY_PROCESSOR_KZCHGR
com.splm.qwcqu.CORE_ACCESS_DFSVBO
com.splm.qwcqu.STORAGE_SERVICE_BRPEFF
com.splm.qwcqu.BROADCAST_MANAGER_QMRUPE
com.splm.qwcqu.TELEPHONY_ACCESS_MRROTE
com.splm.qwcqu.ALERT_PROCESSOR_HQZHJF
com.splm.qwcqu.SCHEDULED_CONTROL_ENSJHR
com.splm.qwcqu.DATA_PROCESSOR_XNLBCR
com.splm.qwcqu.PROXY_MONITOR_GBOPHK
com.splm.qwcqu.ANALYTICS_PROCESSOR_IEVVLB
com.splm.qwcqu.SCHEDULED_HANDLER_JLDLIH
com.splm.qwcqu.SYSTEM_MANAGER_ROREGE
com.splm.qwcqu.USAGE_HANDLER_GYNOKF
com.splm.qwcqu.SCHEDULED_PROVIDER_MWFLFF
com.splm.qwcqu.SYNC_CONTROL_EHWHSF
com.splm.qwcqu.CACHE_CONTROL_PQZZKM
com.splm.qwcqu.TOKEN_MANAGER_CWJDZR
com.splm.qwcqu.ANALYTICS_PROCESSOR_HPNTFA
com.splm.qwcqu.SOCKET_CONTROL_KYQXYG
com.splm.qwcqu.TOKEN_HANDLER_RTJUJA
com.splm.qwcqu.ALERT_ACCESS_HUXHJI
com.splm.qwcqu.PROXY_ACCESS_NAZZOK
com.splm.qwcqu.CLOUD_MONITOR_FVUCYO
com.splm.qwcqu.TOKEN_MANAGER_GSLWCT
com.splm.qwcqu.STORAGE_PROVIDER_QCMVMF
com.splm.qwcqu.SOCKET_PROVIDER_PCIZOF
com.splm.qwcqu.BROADCAST_HANDLER_EXHXRV
com.splm.qwcqu.BROADCAST_SERVICE_RGUJEL
com.splm.qwcqu.PERFORMANCE_ACCESS_XPLRFU
com.splm.qwcqu.SYSTEM_PROCESSOR_PFYZAD
com.splm.qwcqu.BACKGROUND_CONTROL_CMLTIW
com.splm.qwcqu.SECURITY_CONTROL_OPZCLX
com.splm.qwcqu.MOTION_CONTROL_IJXOAW
com.splm.qwcqu.CONTENT_PROVIDER_SLNNTG
com.splm.qwcqu.CACHE_MONITOR_IXFNMM
com.splm.qwcqu.SOCKET_HANDLER_KINVKC
com.splm.qwcqu.SYSTEM_MONITOR_SCYFTM
com.splm.qwcqu.CLOUD_HANDLER_FUGRRC
com.splm.qwcqu.NETWORK_CONTROL_EPNZFP
com.splm.qwcqu.WORK_MANAGER_HLGMAA
com.splm.qwcqu.FILE_MONITOR_QPTRTY
com.splm.qwcqu.TELEPHONY_SERVICE_HNIEBB
com.splm.qwcqu.ANALYTICS_SERVICE_THYPUB
com.splm.qwcqu.CORE_MANAGER_KZXLWA
com.splm.qwcqu.MOTION_HANDLER_GKUDEW
com.splm.qwcqu.SYNC_ACCESS_HXWSRQ
com.splm.qwcqu.TOKEN_ACCESS_IFIWKS
com.splm.qwcqu.MESSAGE_SERVICE_NTRWWL
com.splm.qwcqu.DATA_SERVICE_GLUWDJ
com.splm.qwcqu.FILE_MONITOR_JYOFVR
com.splm.qwcqu.CACHE_HANDLER_FWZMPB
com.splm.qwcqu.TELEPHONY_HANDLER_LDZZLS
com.splm.qwcqu.HARDWARE_ACCESS_VLYWLF
com.splm.qwcqu.PERFORMANCE_SERVICE_KHHECP
com.splm.qwcqu.DEVICE_ACCESS_ARUGFJ
com.splm.qwcqu.FOREGROUND_PROVIDER_FCZKAQ
com.splm.qwcqu.DEVICE_ACCESS_ZBBZIB
com.splm.qwcqu.CORE_ACCESS_YAUUFW
com.splm.qwcqu.TOKEN_PROCESSOR_DIUQDB
com.splm.qwcqu.BROADCAST_SERVICE_RJXLJN
com.splm.qwcqu.SENSOR_HANDLER_DYFECD
com.splm.qwcqu.SYSTEM_MONITOR_MOPHCP
com.splm.qwcqu.SCHEDULED_MONITOR_HFAIFK
com.splm.qwcqu.USAGE_PROVIDER_OOVGIR
com.splm.qwcqu.SYNC_MONITOR_LBJYRS
com.splm.qwcqu.CORE_PROCESSOR_ZELFXI
com.splm.qwcqu.USAGE_HANDLER_YPLSYL
com.splm.qwcqu.TELEPHONY_HANDLER_CWYIRB
com.splm.qwcqu.ALERT_MANAGER_MFPONN
com.splm.qwcqu.ANALYTICS_PROVIDER_IWXOVR
com.splm.qwcqu.ALERT_HANDLER_XWAKAG
com.splm.qwcqu.ALERT_SERVICE_BKBCQX
com.splm.qwcqu.SYSTEM_SERVICE_AXVNPM
com.splm.qwcqu.TOKEN_CONTROL_XANFLC
com.splm.qwcqu.LOCATION_HANDLER_GWEKNE
com.splm.qwcqu.BACKGROUND_PROCESSOR_PFDGOW
com.splm.qwcqu.PERFORMANCE_PROCESSOR_PYGRDB
com.splm.qwcqu.CLOUD_PROCESSOR_WAVYLY
com.splm.qwcqu.PERFORMANCE_ACCESS_WZPYMH
com.splm.qwcqu.ENCRYPTION_CONTROL_CMNLJD
com.splm.qwcqu.BROADCAST_PROCESSOR_WKAFGA
com.splm.qwcqu.BACKGROUND_MONITOR_LQJCCF
com.splm.qwcqu.PUSH_MONITOR_HHMEFO
com.splm.qwcqu.SOCKET_CONTROL_AQFHKI
com.splm.qwcqu.SYNC_CONTROL_AFJETD
com.splm.qwcqu.BACKGROUND_MANAGER_XNEWMZ
com.splm.qwcqu.ANALYTICS_MANAGER_BNLSEV
com.splm.qwcqu.SENSOR_MANAGER_FRMCJE
com.splm.qwcqu.SCHEDULED_ACCESS_ZZPOPA
com.splm.qwcqu.CLOUD_MONITOR_WUVJLH
com.splm.qwcqu.CONTENT_MANAGER_LMITOD
com.splm.qwcqu.PHONE_CONTROL_ABPBPB
com.splm.qwcqu.FILE_PROVIDER_XRPPLS
com.splm.qwcqu.HARDWARE_MONITOR_GHHLWZ
com.splm.qwcqu.SYSTEM_MANAGER_UNZOSB
com.splm.qwcqu.SYSTEM_MANAGER_BTCMMJ
com.splm.qwcqu.DATA_HANDLER_TCVOSU
com.splm.qwcqu.CLOUD_HANDLER_CEBHOU
com.splm.qwcqu.CONTENT_MONITOR_VMBEGZ
com.splm.qwcqu.AUTH_PROVIDER_BUBROB
com.splm.qwcqu.LOCATION_PROVIDER_DCDNPS
com.splm.qwcqu.MOTION_MANAGER_ZRHQXR
com.splm.qwcqu.TELEPHONY_MONITOR_WPFBAM
com.splm.qwcqu.STORAGE_HANDLER_WVJXKH
com.splm.qwcqu.MESSAGE_MONITOR_GRCSNH
com.splm.qwcqu.MOTION_CONTROL_UNEEYM
com.splm.qwcqu.MESSAGE_PROCESSOR_VRGIMZ
com.splm.qwcqu.WORK_ACCESS_IWBUQX
com.splm.qwcqu.CACHE_HANDLER_VDKKWS
com.splm.qwcqu.LOCATION_ACCESS_LSRFVQ
com.splm.qwcqu.USAGE_ACCESS_JFNKRN
com.splm.qwcqu.SENSOR_MONITOR_COQMMF
com.splm.qwcqu.WORK_PROCESSOR_SSQCAZ
com.splm.qwcqu.SYSTEM_PROCESSOR_FAFKIA
com.splm.qwcqu.LOCATION_PROCESSOR_EQZBKP
com.splm.qwcqu.ALERT_HANDLER_RSUZMK
com.splm.qwcqu.HARDWARE_ACCESS_FWOLJH
com.splm.qwcqu.MOTION_ACCESS_JLGAZP
com.splm.qwcqu.AUTH_MANAGER_FRXXDT
com.splm.qwcqu.SYNC_CONTROL_NJDPPB
com.splm.qwcqu.SCHEDULED_MONITOR_TCVNJC
com.splm.qwcqu.SCHEDULED_ACCESS_ZAEKUY
com.splm.qwcqu.HARDWARE_PROCESSOR_ORWGRW
com.splm.qwcqu.SOCKET_MANAGER_KMOBCP
com.splm.qwcqu.CORE_ACCESS_TJRDTQ
com.splm.qwcqu.MOTION_HANDLER_CPDRLQ
com.splm.qwcqu.NETWORK_MANAGER_JMLWNB
com.splm.qwcqu.HARDWARE_ACCESS_JUJHGO
com.splm.qwcqu.CORE_MANAGER_PWCSIG
com.splm.qwcqu.CACHE_ACCESS_UHHETS
com.splm.qwcqu.BROADCAST_PROVIDER_BDCZZL
com.splm.qwcqu.PERFORMANCE_HANDLER_BAXZVM
com.splm.qwcqu.CORE_PROCESSOR_LOBWFL
com.splm.qwcqu.LOCATION_ACCESS_MKHTIH
com.splm.qwcqu.SYSTEM_SERVICE_YQHMKA
com.splm.qwcqu.BACKGROUND_PROVIDER_SXJMLJ
com.splm.qwcqu.PROXY_SERVICE_XYQTYX
com.splm.qwcqu.CLOUD_HANDLER_JKXXEV
com.splm.qwcqu.PROXY_MANAGER_PXINOP
com.splm.qwcqu.PUSH_HANDLER_ARLNNA
com.splm.qwcqu.LOCATION_PROCESSOR_YBHGQJ
com.splm.qwcqu.MOTION_SERVICE_MKERTE
com.splm.qwcqu.TELEPHONY_PROVIDER_GLBVMJ
com.splm.qwcqu.MESSAGE_PROCESSOR_NWGUBU
com.splm.qwcqu.BACKGROUND_MONITOR_DHFBWX
com.splm.qwcqu.AUTH_ACCESS_ADRKZL
com.splm.qwcqu.FILE_MONITOR_XTSXGP
com.splm.qwcqu.ENCRYPTION_HANDLER_OSCIPY
com.splm.qwcqu.ANALYTICS_ACCESS_OJIQTV
com.splm.qwcqu.MOTION_CONTROL_LGARRZ
com.splm.qwcqu.STORAGE_ACCESS_XPXDUG
com.splm.qwcqu.TELEPHONY_PROCESSOR_NEJFWJ
com.splm.qwcqu.CONTENT_ACCESS_SCHSDT
com.splm.qwcqu.DEVICE_ACCESS_KEYMCT
com.splm.qwcqu.GEO_FENCE_MONITOR_MNUHXD
com.splm.qwcqu.FOREGROUND_PROCESSOR_DMABIA
com.splm.qwcqu.SCHEDULED_CONTROL_DTXDXR
com.splm.qwcqu.NETWORK_HANDLER_KXJEKQ
com.splm.qwcqu.AUTH_PROVIDER_OPKDZX
com.splm.qwcqu.USAGE_MONITOR_LKUDAV
com.splm.qwcqu.AUTH_CONTROL_KOQFVU
com.splm.qwcqu.LOCATION_PROVIDER_EZKVRT
com.splm.qwcqu.MOTION_PROVIDER_VLZNCZ
com.splm.qwcqu.CACHE_MANAGER_KYVZVT
com.splm.qwcqu.ALERT_MONITOR_NPARCB
com.splm.qwcqu.CORE_PROVIDER_WKCJTN
com.splm.qwcqu.STORAGE_CONTROL_CTSRRJ
com.splm.qwcqu.GEO_FENCE_HANDLER_BXZUKP
com.splm.qwcqu.FOREGROUND_PROVIDER_GCBBKA
com.splm.qwcqu.SENSOR_PROVIDER_PIZXQL
com.splm.qwcqu.ENCRYPTION_CONTROL_GTWVUW
com.splm.qwcqu.GEO_FENCE_MANAGER_KRXGOI
com.splm.qwcqu.SYSTEM_HANDLER_OGJFSC
com.splm.qwcqu.SENSOR_PROCESSOR_QQDAXT
com.splm.qwcqu.ALERT_SERVICE_NDFEDB
com.splm.qwcqu.BACKGROUND_ACCESS_IQATDN
com.splm.qwcqu.AUTH_ACCESS_OFOWCL
com.splm.qwcqu.FILE_PROCESSOR_XSWFFQ
com.splm.qwcqu.DEVICE_CONTROL_EKDQFM
com.splm.qwcqu.SECURITY_PROCESSOR_ZACFPT
com.splm.qwcqu.SYNC_MANAGER_UBAUCE
com.splm.qwcqu.AUTH_PROVIDER_ONQALQ
com.splm.qwcqu.AUTH_CONTROL_BSAAFW
com.splm.qwcqu.SYNC_SERVICE_TFWIGE
com.splm.qwcqu.SENSOR_MANAGER_HUJGKE
com.splm.qwcqu.LOCATION_CONTROL_UJJTQK
com.splm.qwcqu.MESSAGE_MONITOR_ZNGZLW
com.splm.qwcqu.DATA_PROVIDER_JLZLKE
com.splm.qwcqu.BROADCAST_ACCESS_DXOEMF
com.splm.qwcqu.USAGE_PROVIDER_YMGWHL
com.splm.qwcqu.SOCKET_HANDLER_SNHWEW
com.splm.qwcqu.MESSAGE_CONTROL_PBNCNL
com.splm.qwcqu.CACHE_SERVICE_VVPPQO
com.splm.qwcqu.STORAGE_CONTROL_QGGQRG
com.splm.qwcqu.ENCRYPTION_CONTROL_HQHFPR
com.splm.qwcqu.AUTH_PROVIDER_JEOXCV
com.splm.qwcqu.CACHE_PROVIDER_OMSQVM
com.splm.qwcqu.STORAGE_CONTROL_NHEBIS
com.splm.qwcqu.SYNC_SERVICE_FGUFQF
com.splm.qwcqu.AUTH_MONITOR_QJIVSI
com.splm.qwcqu.BROADCAST_MANAGER_NIEQZD
com.splm.qwcqu.WORK_SERVICE_AOYSUN
com.splm.qwcqu.CLOUD_SERVICE_WLSDDC
com.splm.qwcqu.FOREGROUND_ACCESS_IEFHLO
com.splm.qwcqu.AUTH_MONITOR_JYXVIJ
com.splm.qwcqu.TELEPHONY_HANDLER_RGGEJB
com.splm.qwcqu.ALERT_MONITOR_NXKCQI
com.splm.qwcqu.PROXY_SERVICE_SQXQWA
com.splm.qwcqu.SENSOR_SERVICE_FGMBNG
com.splm.qwcqu.CACHE_HANDLER_JVSEZG
com.splm.qwcqu.NETWORK_CONTROL_VIFDBW
com.splm.qwcqu.FILE_ACCESS_RRKNOI
com.splm.qwcqu.TELEPHONY_MONITOR_JBYZAZ
com.splm.qwcqu.TELEPHONY_PROCESSOR_HNNBMR
com.splm.qwcqu.CONTENT_SERVICE_QNPUJQ
com.splm.qwcqu.MESSAGE_CONTROL_BFQKEQ
com.splm.qwcqu.PERFORMANCE_PROCESSOR_PJCTCG
com.splm.qwcqu.SYNC_MANAGER_BAPQWI
com.splm.qwcqu.CACHE_CONTROL_AVVXJX
com.splm.qwcqu.DATA_HANDLER_FYRINK
com.splm.qwcqu.BROADCAST_ACCESS_HUQBCV
com.splm.qwcqu.PROXY_HANDLER_QUPPOV
com.splm.qwcqu.CONTENT_MANAGER_SQKKFJ
com.splm.qwcqu.DATA_CONTROL_WOUPBZ
com.splm.qwcqu.DATA_PROVIDER_GTOYXD
com.splm.qwcqu.MOTION_MONITOR_XSJOAG
com.splm.qwcqu.FILE_SERVICE_FUOGCV
com.splm.qwcqu.ANALYTICS_SERVICE_OIPBRG
com.splm.qwcqu.ANALYTICS_MONITOR_RQMHFW
com.splm.qwcqu.NETWORK_SERVICE_KBXCGJ
com.splm.qwcqu.CLOUD_SERVICE_OVEAWF
com.splm.qwcqu.DEVICE_HANDLER_YHDHFI
com.splm.qwcqu.FILE_MONITOR_JCNDAG
com.splm.qwcqu.GEO_FENCE_PROCESSOR_CXIWDA
com.splm.qwcqu.CORE_SERVICE_KVVKYU
com.splm.qwcqu.ALERT_PROCESSOR_LAAUWY
com.splm.qwcqu.FOREGROUND_PROCESSOR_YTVPNR
com.splm.qwcqu.PUSH_SERVICE_EEOVBT
com.splm.qwcqu.TOKEN_PROCESSOR_GBHJJA
com.splm.qwcqu.FILE_MANAGER_ZHUIVG
com.splm.qwcqu.STORAGE_MONITOR_LLQPYC
com.splm.qwcqu.SECURITY_SERVICE_RSOARG
com.splm.qwcqu.SENSOR_PROCESSOR_IIZQFQ
com.splm.qwcqu.MESSAGE_HANDLER_PDGYWV
com.splm.qwcqu.CONTENT_PROCESSOR_BUQTAA
com.splm.qwcqu.BACKGROUND_MONITOR_SBWJCS
com.splm.qwcqu.MOTION_PROVIDER_CPMGSU
com.splm.qwcqu.STORAGE_MANAGER_EVCAYF
com.splm.qwcqu.HARDWARE_ACCESS_NETAHH
com.splm.qwcqu.FILE_PROCESSOR_FEOIGJ
com.splm.qwcqu.PHONE_HANDLER_CXWJPX
com.splm.qwcqu.AUTH_HANDLER_UJQHAR
com.splm.qwcqu.GEO_FENCE_CONTROL_AADYGW
com.splm.qwcqu.MESSAGE_PROVIDER_GSQZEF
com.splm.qwcqu.MOTION_PROVIDER_DOGQJL
com.splm.qwcqu.FILE_MANAGER_YVPBUR
com.splm.qwcqu.HARDWARE_CONTROL_TEQHUC
com.splm.qwcqu.WORK_HANDLER_ECALQG
com.splm.qwcqu.PERFORMANCE_PROCESSOR_YBQPXG
com.splm.qwcqu.MESSAGE_ACCESS_EWYEWM
com.splm.qwcqu.HARDWARE_MANAGER_ISHPVC
com.splm.qwcqu.SYSTEM_PROVIDER_MYUDHP
com.splm.qwcqu.TELEPHONY_SERVICE_WBXFUR
com.splm.qwcqu.LOCATION_PROCESSOR_ZNGQOO
com.splm.qwcqu.BROADCAST_SERVICE_JBDAIB
com.splm.qwcqu.BROADCAST_CONTROL_JGQZZJ
com.splm.qwcqu.CACHE_ACCESS_ILKKYU
com.splm.qwcqu.AUTH_MANAGER_GARDGU
com.splm.qwcqu.PROXY_SERVICE_FWRDSB
com.splm.qwcqu.TOKEN_HANDLER_XTQLRW
com.splm.qwcqu.SCHEDULED_PROVIDER_QJGDKS
com.splm.qwcqu.SYNC_PROVIDER_XNSWFI
com.splm.qwcqu.DEVICE_SERVICE_USLBQC
com.splm.qwcqu.FILE_MONITOR_ONVCXI
com.splm.qwcqu.ALERT_MANAGER_NTMYAK
com.splm.qwcqu.HARDWARE_HANDLER_DUWLLQ
com.splm.qwcqu.DEVICE_HANDLER_IVXUDB
com.splm.qwcqu.SYNC_MONITOR_TXCHQA
com.splm.qwcqu.AUTH_ACCESS_PJLSWL
com.splm.qwcqu.GEO_FENCE_PROVIDER_VMFTOK
com.splm.qwcqu.SECURITY_SERVICE_HKJMLK
com.splm.qwcqu.STORAGE_HANDLER_GDETUZ
com.splm.qwcqu.SCHEDULED_MANAGER_FSOWAF
com.splm.qwcqu.TELEPHONY_PROVIDER_MILYGV
com.splm.qwcqu.STORAGE_PROVIDER_MRVSZK
com.splm.qwcqu.USAGE_MANAGER_NBGTGG
com.splm.qwcqu.USAGE_HANDLER_QOKJEP
com.splm.qwcqu.NETWORK_SERVICE_KMTBAM
com.splm.qwcqu.ALERT_PROVIDER_LBFNLT
com.splm.qwcqu.TOKEN_ACCESS_EMPTDK
com.splm.qwcqu.PERFORMANCE_ACCESS_DOXWNN
com.splm.qwcqu.TOKEN_PROCESSOR_WZOFQE
com.splm.qwcqu.BROADCAST_HANDLER_JVYSUO
com.splm.qwcqu.TELEPHONY_HANDLER_NOGXTY
com.splm.qwcqu.FOREGROUND_SERVICE_KVFPOP
com.splm.qwcqu.PUSH_SERVICE_IOXHVI
com.splm.qwcqu.SYSTEM_SERVICE_YMRGDZ
com.splm.qwcqu.SENSOR_PROCESSOR_ZHFVRF
com.splm.qwcqu.GEO_FENCE_PROCESSOR_YYPGHF
com.splm.qwcqu.TOKEN_HANDLER_ZMDATP
com.splm.qwcqu.HARDWARE_PROVIDER_UNFJKE
com.splm.qwcqu.PHONE_HANDLER_BQKTEP
com.splm.qwcqu.BACKGROUND_CONTROL_JURVAR
com.splm.qwcqu.LOCATION_HANDLER_JEGLQB
com.splm.qwcqu.SECURITY_ACCESS_AOBKXK
com.splm.qwcqu.PHONE_PROCESSOR_BGUPWI
com.splm.qwcqu.AUTH_CONTROL_NSVXRZ
com.splm.qwcqu.MOTION_CONTROL_XJQKIX
com.splm.qwcqu.MESSAGE_PROCESSOR_SZOIXW
com.splm.qwcqu.STORAGE_HANDLER_OKJMOY
com.splm.qwcqu.CONTENT_PROVIDER_HEBXIO
com.splm.qwcqu.PUSH_PROCESSOR_PICMBS
com.splm.qwcqu.SYNC_MONITOR_ZDZDNK
com.splm.qwcqu.NETWORK_PROVIDER_ZSDGVR
com.splm.qwcqu.TOKEN_HANDLER_SSDXBM
com.splm.qwcqu.ALERT_SERVICE_HJOAUP
com.splm.qwcqu.PUSH_MANAGER_EJXMEM
com.splm.qwcqu.FOREGROUND_CONTROL_FKYIPR
com.splm.qwcqu.CORE_MANAGER_AOTRYU
com.splm.qwcqu.PUSH_MONITOR_QVFYKR
com.splm.qwcqu.FILE_CONTROL_TULSXV
com.splm.qwcqu.FILE_PROCESSOR_FHCEMP
com.splm.qwcqu.DATA_CONTROL_AXPGMI
com.splm.qwcqu.MESSAGE_HANDLER_MWLGQQ
com.splm.qwcqu.DATA_PROCESSOR_LQGAHE
com.splm.qwcqu.SENSOR_CONTROL_PLJCUG
com.splm.qwcqu.AUTH_PROVIDER_VLPGVY
com.splm.qwcqu.AUTH_SERVICE_XACUGY
com.splm.qwcqu.ALERT_PROVIDER_MYLHRX
com.splm.qwcqu.FOREGROUND_ACCESS_VKEYUD
com.splm.qwcqu.HARDWARE_SERVICE_GBTXEF
com.splm.qwcqu.HARDWARE_PROCESSOR_EYEVKH
com.splm.qwcqu.PROXY_PROVIDER_LEBVRV
com.splm.qwcqu.SECURITY_ACCESS_NNFJRP
com.splm.qwcqu.SOCKET_SERVICE_KVDXZC
com.splm.qwcqu.NETWORK_PROCESSOR_LARYFV
com.splm.qwcqu.DATA_MONITOR_EJGEWC
com.splm.qwcqu.SYNC_MANAGER_SMHMJH
com.splm.qwcqu.TELEPHONY_CONTROL_YKMFRV
com.splm.qwcqu.AUTH_HANDLER_ZDHENW
com.splm.qwcqu.SYNC_PROCESSOR_BSWSOA
com.splm.qwcqu.ENCRYPTION_HANDLER_DUDGEQ
com.splm.qwcqu.CLOUD_HANDLER_NMYJBP
com.splm.qwcqu.PHONE_MONITOR_XVMERX
com.splm.qwcqu.BROADCAST_CONTROL_UHUYEK
com.splm.qwcqu.SCHEDULED_PROCESSOR_LIXBKF
com.splm.qwcqu.ENCRYPTION_MANAGER_ZTQLNA
com.splm.qwcqu.PROXY_CONTROL_PWHMCC
com.splm.qwcqu.MESSAGE_ACCESS_ZBJZZR
com.splm.qwcqu.SCHEDULED_PROVIDER_FROKTU
com.splm.qwcqu.DEVICE_ACCESS_EZETGP
com.splm.qwcqu.DATA_ACCESS_ZNFVVT
com.splm.qwcqu.HARDWARE_MANAGER_FFYTHK
com.splm.qwcqu.SENSOR_ACCESS_OOTMYE
com.splm.qwcqu.ENCRYPTION_CONTROL_LWHUQN
com.splm.qwcqu.GEO_FENCE_MONITOR_HHISMI
com.splm.qwcqu.CACHE_CONTROL_TEHTUG
com.splm.qwcqu.STORAGE_CONTROL_RJKGRC
com.splm.qwcqu.CLOUD_SERVICE_AFPZWS
com.splm.qwcqu.CONTENT_MONITOR_ZRLSKT
com.splm.qwcqu.WORK_PROCESSOR_HRBMTI
com.splm.qwcqu.MOTION_PROCESSOR_VMMFQX
com.splm.qwcqu.PERFORMANCE_ACCESS_CTXGZI
com.splm.qwcqu.NETWORK_PROCESSOR_UXAPRO
com.splm.qwcqu.SOCKET_HANDLER_VWQLHB
com.splm.qwcqu.USAGE_SERVICE_SCUFZC
com.splm.qwcqu.DEVICE_SERVICE_INTTGN
com.splm.qwcqu.FILE_HANDLER_MWUXUH
com.splm.qwcqu.PUSH_ACCESS_ADUHVA
com.splm.qwcqu.PROXY_CONTROL_ZGGPCH
com.splm.qwcqu.SENSOR_ACCESS_IEDJJY
com.splm.qwcqu.DATA_MONITOR_NNFRBQ
com.splm.qwcqu.GEO_FENCE_CONTROL_CZZPAK
com.splm.qwcqu.AUTH_SERVICE_WQGBEO
com.splm.qwcqu.GEO_FENCE_ACCESS_MHIHLP
com.splm.qwcqu.AUTH_PROCESSOR_HRKWWQ
com.splm.qwcqu.ALERT_HANDLER_QIHLST
com.splm.qwcqu.MOTION_SERVICE_ALPBEG
com.splm.qwcqu.CORE_HANDLER_VLPXDF
com.splm.qwcqu.SCHEDULED_ACCESS_AZVJGI
com.splm.qwcqu.TELEPHONY_CONTROL_PICGNQ
com.splm.qwcqu.LOCATION_PROVIDER_MLGASZ
com.splm.qwcqu.CORE_MANAGER_DQFDKQ
com.splm.qwcqu.CLOUD_HANDLER_ZQHOYE
com.splm.qwcqu.CACHE_CONTROL_XRQFUB
com.splm.qwcqu.FOREGROUND_PROCESSOR_HMIQYI
com.splm.qwcqu.PERFORMANCE_PROCESSOR_GGWAHT
com.splm.qwcqu.USAGE_MONITOR_PPLZBZ
com.splm.qwcqu.PUSH_SERVICE_PUVYBN
com.splm.qwcqu.PROXY_SERVICE_HDAAEI
com.splm.qwcqu.TELEPHONY_PROVIDER_UZJXAK
com.splm.qwcqu.USAGE_MANAGER_VATTQX
com.splm.qwcqu.BROADCAST_HANDLER_KXMUYQ
com.splm.qwcqu.SYNC_MONITOR_CLVWUB
com.splm.qwcqu.AUTH_CONTROL_QTCVAU
com.splm.qwcqu.PERFORMANCE_HANDLER_IKOWAY
com.splm.qwcqu.FOREGROUND_MONITOR_ZWHFMO
com.splm.qwcqu.MESSAGE_MONITOR_RVQFXM
com.splm.qwcqu.HARDWARE_SERVICE_JFBKSF
com.splm.qwcqu.TOKEN_SERVICE_WCTMTX
com.splm.qwcqu.NETWORK_PROCESSOR_GUUNYV
com.splm.qwcqu.FILE_PROCESSOR_OVTJXN
com.splm.qwcqu.GEO_FENCE_HANDLER_PACDUC
com.splm.qwcqu.SENSOR_SERVICE_NXEHAL
com.splm.qwcqu.STORAGE_MONITOR_RNPBEU
com.splm.qwcqu.WORK_MANAGER_IURQQV
com.splm.qwcqu.NETWORK_ACCESS_WURMTP
com.splm.qwcqu.SYNC_SERVICE_QAXDVF
com.splm.qwcqu.BROADCAST_PROCESSOR_KFCEEG
com.splm.qwcqu.CONTENT_MONITOR_HKGTRH
com.splm.qwcqu.ANALYTICS_ACCESS_ZHZXJC
com.splm.qwcqu.STORAGE_HANDLER_VXRUNY
com.splm.qwcqu.FOREGROUND_CONTROL_YJYSYG
com.splm.qwcqu.SCHEDULED_CONTROL_KXXASH
com.splm.qwcqu.BROADCAST_CONTROL_FDEFOB
com.splm.qwcqu.ANALYTICS_CONTROL_YXHEZJ
com.splm.qwcqu.DATA_PROVIDER_EOBWIN
com.splm.qwcqu.DATA_ACCESS_XLVUUN
com.splm.qwcqu.SOCKET_SERVICE_YVGLYV
com.splm.qwcqu.SCHEDULED_SERVICE_QWAIVP
com.splm.qwcqu.CONTENT_PROVIDER_KLPJYS
com.splm.qwcqu.CORE_MONITOR_NUDMMM
com.splm.qwcqu.BROADCAST_CONTROL_GVJKYX
com.splm.qwcqu.BACKGROUND_CONTROL_ARCLNV
com.splm.qwcqu.DEVICE_HANDLER_FJMNAK
com.splm.qwcqu.MESSAGE_PROVIDER_ORCZXX
com.splm.qwcqu.SOCKET_ACCESS_JURMLM
com.splm.qwcqu.STORAGE_CONTROL_RJRBTE
com.splm.qwcqu.HARDWARE_MONITOR_OWFCOV
com.splm.qwcqu.PUSH_CONTROL_QXNNEH
com.splm.qwcqu.STORAGE_ACCESS_EMNQJP
com.splm.qwcqu.ALERT_HANDLER_HDCQQJ
com.splm.qwcqu.LOCATION_MANAGER_PMZPHH
com.splm.qwcqu.AUTH_MANAGER_WEDKXC
com.splm.qwcqu.MESSAGE_MANAGER_FWJJPR
com.splm.qwcqu.GEO_FENCE_PROCESSOR_XWJYJC
com.splm.qwcqu.HARDWARE_PROCESSOR_UJDILH
com.splm.qwcqu.GEO_FENCE_HANDLER_IECZUV
com.splm.qwcqu.FOREGROUND_ACCESS_BKLTAN
com.splm.qwcqu.MOTION_MANAGER_WDDFMM
com.splm.qwcqu.ENCRYPTION_SERVICE_EDGGPM
com.splm.qwcqu.CACHE_MONITOR_MZKOHU
com.splm.qwcqu.DATA_MANAGER_JFBXMM
com.splm.qwcqu.GEO_FENCE_CONTROL_KMYYCG
com.splm.qwcqu.SOCKET_HANDLER_OANPYI
com.splm.qwcqu.ENCRYPTION_MANAGER_HFFBZL
com.splm.qwcqu.FILE_MONITOR_BTWVIO
com.splm.qwcqu.CLOUD_CONTROL_VOPGHT
com.splm.qwcqu.CLOUD_CONTROL_SGXPZO
com.splm.qwcqu.MOTION_ACCESS_ZKXZAM
com.splm.qwcqu.ALERT_HANDLER_PKWSDI
com.splm.qwcqu.LOCATION_SERVICE_ZEFWFA
com.splm.qwcqu.MESSAGE_ACCESS_YQQKET
com.splm.qwcqu.GEO_FENCE_HANDLER_JDAQYD
com.splm.qwcqu.GEO_FENCE_PROVIDER_AJZSFS
com.splm.qwcqu.SENSOR_CONTROL_UDBRND
com.splm.qwcqu.PROXY_SERVICE_HRASOG
com.splm.qwcqu.ALERT_PROCESSOR_NGMMVF
com.splm.qwcqu.SOCKET_PROCESSOR_GEVATC
com.splm.qwcqu.MESSAGE_PROVIDER_LWSRVR
com.splm.qwcqu.FOREGROUND_ACCESS_EWQPIN
com.splm.qwcqu.LOCATION_PROCESSOR_CPDPPS
com.splm.qwcqu.STORAGE_MONITOR_YMYPEM
com.splm.qwcqu.CONTENT_MANAGER_ZNNRRC
com.splm.qwcqu.MOTION_MANAGER_CZIOFT
com.splm.qwcqu.ANALYTICS_MANAGER_YELTBX
com.splm.qwcqu.BROADCAST_CONTROL_BXSXSA
com.splm.qwcqu.SENSOR_MANAGER_GAPQZX
com.splm.qwcqu.FILE_MONITOR_AJGROD
com.splm.qwcqu.HARDWARE_PROCESSOR_IQROVV
com.splm.qwcqu.SCHEDULED_SERVICE_LXSFJD
com.splm.qwcqu.MESSAGE_ACCESS_NSTHUM
com.splm.qwcqu.SYSTEM_ACCESS_FKKDJF
com.splm.qwcqu.GEO_FENCE_PROVIDER_QVXWTX
com.splm.qwcqu.ENCRYPTION_CONTROL_HXJDYS
com.splm.qwcqu.USAGE_CONTROL_DGXSJH
com.splm.qwcqu.NETWORK_PROVIDER_SWSOYS
com.splm.qwcqu.CORE_MONITOR_GMAOAS
com.splm.qwcqu.PERFORMANCE_MONITOR_BLRHCN
com.splm.qwcqu.CLOUD_PROVIDER_VHNEVP
com.splm.qwcqu.BACKGROUND_PROVIDER_DTXFMW
com.splm.qwcqu.CORE_CONTROL_NEBHTE
com.splm.qwcqu.USAGE_HANDLER_QYYDZG
com.splm.qwcqu.HARDWARE_SERVICE_VSBQLG
com.splm.qwcqu.PUSH_SERVICE_DRKLJN
com.splm.qwcqu.SYNC_ACCESS_RYOOUU
com.splm.qwcqu.FOREGROUND_CONTROL_HLUVJZ
com.splm.qwcqu.SECURITY_MONITOR_LKLRKN
com.splm.qwcqu.NETWORK_HANDLER_XBVOOL
com.splm.qwcqu.PHONE_CONTROL_EGMXKB
com.splm.qwcqu.BROADCAST_SERVICE_VMSTVT
com.splm.qwcqu.WORK_PROCESSOR_AQZEWX
com.splm.qwcqu.SYNC_MANAGER_YFDFSD
com.splm.qwcqu.TOKEN_MONITOR_UFTCRZ
com.splm.qwcqu.DEVICE_ACCESS_UKAROE
com.splm.qwcqu.CLOUD_MONITOR_VUBTMC
com.splm.qwcqu.FILE_SERVICE_IYSIIO
com.splm.qwcqu.FILE_PROCESSOR_HCNTPC
com.splm.qwcqu.CACHE_CONTROL_TMFELE
com.splm.qwcqu.GEO_FENCE_SERVICE_ZHLOLK
com.splm.qwcqu.USAGE_ACCESS_OMQWYK
com.splm.qwcqu.SYSTEM_SERVICE_ESGOSO
com.splm.qwcqu.ALERT_ACCESS_KMIUNN
com.splm.qwcqu.PHONE_MONITOR_XINFXD
com.splm.qwcqu.PUSH_MONITOR_XFCKMF
com.splm.qwcqu.PHONE_SERVICE_FFCOTI
com.splm.qwcqu.ENCRYPTION_MANAGER_XBMFKB
com.splm.qwcqu.TOKEN_MANAGER_SZUBZR
com.splm.qwcqu.FILE_HANDLER_FQSEHX
com.splm.qwcqu.SCHEDULED_ACCESS_DTVOSC
com.splm.qwcqu.AUTH_PROVIDER_JGQVCF
com.splm.qwcqu.FOREGROUND_SERVICE_WWTRFN
com.splm.qwcqu.TELEPHONY_MONITOR_YQVIOC
com.splm.qwcqu.PROXY_PROVIDER_EYPFLC
com.splm.qwcqu.ANALYTICS_MANAGER_EZRSEE
com.splm.qwcqu.GEO_FENCE_ACCESS_JHBLEZ
com.splm.qwcqu.FILE_HANDLER_ZMGXVE
com.splm.qwcqu.USAGE_SERVICE_SRYWGH
com.splm.qwcqu.FILE_HANDLER_TTCJXN
com.splm.qwcqu.CLOUD_ACCESS_DRWMUW
com.splm.qwcqu.SYSTEM_PROVIDER_ACBQVY
com.splm.qwcqu.MESSAGE_PROCESSOR_ICYSLD
com.splm.qwcqu.ANALYTICS_SERVICE_FXWNXE
com.splm.qwcqu.DATA_CONTROL_MXBNVT
com.splm.qwcqu.LOCATION_PROCESSOR_AXJIPH
com.splm.qwcqu.DATA_CONTROL_NUHPCP
com.splm.qwcqu.ANALYTICS_SERVICE_QNNRYR
com.splm.qwcqu.PUSH_PROCESSOR_VFVGZM
com.splm.qwcqu.CORE_ACCESS_JPMZLT
com.splm.qwcqu.SECURITY_MANAGER_WAJHMX
com.splm.qwcqu.AUTH_ACCESS_XYSVXT
com.splm.qwcqu.FILE_SERVICE_DRFHFF
com.splm.qwcqu.CONTENT_HANDLER_LXOBDA
com.splm.qwcqu.BROADCAST_SERVICE_KEVYCA
com.splm.qwcqu.AUTH_ACCESS_EISGEQ
com.splm.qwcqu.SCHEDULED_HANDLER_CZMSST
com.splm.qwcqu.MESSAGE_MONITOR_GONNHV
com.splm.qwcqu.CONTENT_ACCESS_LKVSRA
com.splm.qwcqu.BROADCAST_HANDLER_FTFBMS
com.splm.qwcqu.BACKGROUND_ACCESS_FBPDHZ
com.splm.qwcqu.DATA_MANAGER_GQLKZQ
com.splm.qwcqu.PHONE_PROVIDER_TCJTUG
com.splm.qwcqu.BACKGROUND_ACCESS_FNTDJK
com.splm.qwcqu.PHONE_MONITOR_NQPKTB
com.splm.qwcqu.LOCATION_PROVIDER_AMUEQQ
com.splm.qwcqu.BROADCAST_PROVIDER_PVOGBB
com.splm.qwcqu.FOREGROUND_HANDLER_FIEGBD
com.splm.qwcqu.ALERT_CONTROL_IVBEOY
com.splm.qwcqu.LOCATION_MANAGER_YQSTHP
com.splm.qwcqu.TOKEN_PROVIDER_XHWMMT
com.splm.qwcqu.BACKGROUND_MANAGER_RYJFVN
com.splm.qwcqu.NETWORK_ACCESS_QGLSOF
com.splm.qwcqu.DEVICE_MONITOR_BEPPEE
com.splm.qwcqu.CACHE_PROCESSOR_TLZAKB
com.splm.qwcqu.SOCKET_MANAGER_OTKSJU
com.splm.qwcqu.MESSAGE_PROVIDER_JRYXJQ
com.splm.qwcqu.CACHE_PROCESSOR_VPAMHM
com.splm.qwcqu.ENCRYPTION_PROCESSOR_FXXWQQ
com.splm.qwcqu.MESSAGE_CONTROL_BNYELS
com.splm.qwcqu.FOREGROUND_SERVICE_BZIGIY
com.splm.qwcqu.AUTH_ACCESS_VRHSKF
com.splm.qwcqu.FILE_PROVIDER_VUDFUB
com.splm.qwcqu.HARDWARE_PROCESSOR_XVEUAR
com.splm.qwcqu.SYSTEM_PROCESSOR_USYVQV
com.splm.qwcqu.LOCATION_PROVIDER_TCPZIX
com.splm.qwcqu.ANALYTICS_ACCESS_XKIOEL
com.splm.qwcqu.MOTION_PROCESSOR_ALMXUO
com.splm.qwcqu.ALERT_SERVICE_DZEGVZ
com.splm.qwcqu.CLOUD_SERVICE_QMOASS
com.splm.qwcqu.SYNC_MANAGER_MEIFOH
com.splm.qwcqu.SYNC_ACCESS_KDKIRA
com.splm.qwcqu.CORE_MONITOR_XCPMEA
com.splm.qwcqu.HARDWARE_PROCESSOR_TTCLJW
com.splm.qwcqu.NETWORK_ACCESS_FKOGTE
com.splm.qwcqu.DATA_HANDLER_EEITQO
com.splm.qwcqu.NETWORK_CONTROL_XSCGCM
com.splm.qwcqu.DEVICE_ACCESS_SKXYOH
com.splm.qwcqu.ANALYTICS_PROCESSOR_KYETZM
com.splm.qwcqu.WORK_MONITOR_BNYAFI
com.splm.qwcqu.ANALYTICS_PROVIDER_JHBPUJ
com.splm.qwcqu.USAGE_MONITOR_KMXHFD
com.splm.qwcqu.HARDWARE_CONTROL_WPCBWW
com.splm.qwcqu.FOREGROUND_PROVIDER_LTOZJR
com.splm.qwcqu.STORAGE_SERVICE_XSWCGV
com.splm.qwcqu.DATA_HANDLER_CGDADO
com.splm.qwcqu.DATA_PROVIDER_VFYTJO
com.splm.qwcqu.CACHE_PROCESSOR_TIRNLS
com.splm.qwcqu.SYSTEM_MONITOR_GRONGL
com.splm.qwcqu.DATA_PROCESSOR_GRFGJR
com.splm.qwcqu.SOCKET_ACCESS_EUDGNS
com.splm.qwcqu.LOCATION_MONITOR_TCZVLV
com.splm.qwcqu.SYSTEM_MANAGER_NNGRRD
com.splm.qwcqu.USAGE_MANAGER_MVUDBE
com.splm.qwcqu.SECURITY_PROVIDER_LCHLOH
com.splm.qwcqu.NETWORK_SERVICE_NFEGVK
com.splm.qwcqu.SECURITY_MANAGER_XTECUF
com.splm.qwcqu.FOREGROUND_CONTROL_NZUMVB
com.splm.qwcqu.NETWORK_MANAGER_SIADBR
com.splm.qwcqu.USAGE_SERVICE_NWISRD
com.splm.qwcqu.SYNC_HANDLER_ZULRXS
com.splm.qwcqu.WORK_MANAGER_DYRISA
com.splm.qwcqu.TELEPHONY_PROCESSOR_WNTYQE
com.splm.qwcqu.FOREGROUND_CONTROL_BWCBRY
com.splm.qwcqu.ALERT_MONITOR_OAAJCT
com.splm.qwcqu.SYSTEM_PROCESSOR_PXBOVG
com.splm.qwcqu.TOKEN_MONITOR_WSALQV
com.splm.qwcqu.FOREGROUND_CONTROL_OTHWVD
com.splm.qwcqu.DEVICE_MANAGER_YLHYIP
com.splm.qwcqu.AUTH_ACCESS_FZDDJX
com.splm.qwcqu.PROXY_PROVIDER_XXBBEG
com.splm.qwcqu.GEO_FENCE_HANDLER_BGJWXS
com.splm.qwcqu.HARDWARE_CONTROL_IRYKSK
com.splm.qwcqu.SECURITY_CONTROL_VUMMNG
com.splm.qwcqu.FOREGROUND_PROVIDER_EVCDEZ
com.splm.qwcqu.WORK_MONITOR_KBQINN
com.splm.qwcqu.SYSTEM_PROVIDER_JIWRBR
com.splm.qwcqu.SYNC_MONITOR_TDTKEJ
com.splm.qwcqu.MOTION_ACCESS_CSTRGJ
com.splm.qwcqu.ENCRYPTION_PROCESSOR_YLLFGX
com.splm.qwcqu.CONTENT_CONTROL_QTLXAW
com.splm.qwcqu.SYNC_CONTROL_JTGDNA
com.splm.qwcqu.GEO_FENCE_PROCESSOR_STMKZM
com.splm.qwcqu.CORE_CONTROL_ZAWFFJ
com.splm.qwcqu.BROADCAST_MANAGER_SJQTVT
com.splm.qwcqu.SECURITY_CONTROL_YZWPRJ
com.splm.qwcqu.ENCRYPTION_CONTROL_YWUWHR
com.splm.qwcqu.PUSH_SERVICE_BFQXTH
com.splm.qwcqu.STORAGE_CONTROL_WBVKUY
com.splm.qwcqu.SOCKET_PROVIDER_RYVZAN
com.splm.qwcqu.ENCRYPTION_PROVIDER_KYCZAV
com.splm.qwcqu.MESSAGE_MANAGER_CNIYBJ
com.splm.qwcqu.MOTION_PROVIDER_YFJQJR
com.splm.qwcqu.DATA_MANAGER_SCVJJD
com.splm.qwcqu.SYSTEM_MANAGER_QPTFSV
com.splm.qwcqu.ALERT_CONTROL_SYQOEW
com.splm.qwcqu.SENSOR_PROVIDER_VRFVVJ
com.splm.qwcqu.SCHEDULED_MONITOR_UAAZXK
com.splm.qwcqu.ALERT_PROVIDER_NJWPTV
com.splm.qwcqu.PHONE_MONITOR_WRFZZE
com.splm.qwcqu.BACKGROUND_ACCESS_FBRRLH
com.splm.qwcqu.BACKGROUND_ACCESS_TTTKWI
com.splm.qwcqu.DEVICE_MANAGER_YKWCTX
com.splm.qwcqu.NETWORK_HANDLER_MUGXAQ
com.splm.qwcqu.CORE_SERVICE_CMHHSI
com.splm.qwcqu.DEVICE_SERVICE_XNORQJ
com.splm.qwcqu.ALERT_MONITOR_HGXSNU
com.splm.qwcqu.DATA_MANAGER_LJYXTY
com.splm.qwcqu.ALERT_ACCESS_QYEKLA
com.splm.qwcqu.STORAGE_HANDLER_LZIBMW
com.splm.qwcqu.AUTH_MANAGER_XSBLKU
com.splm.qwcqu.SENSOR_CONTROL_YZWHPA
com.splm.qwcqu.CACHE_PROVIDER_AGMULB
com.splm.qwcqu.ENCRYPTION_ACCESS_MPSIFG
com.splm.qwcqu.AUTH_SERVICE_TWXGON
com.splm.qwcqu.SOCKET_PROVIDER_MCNKXJ
com.splm.qwcqu.CLOUD_MANAGER_KBOSYT
com.splm.qwcqu.DEVICE_SERVICE_CKLZBB
com.splm.qwcqu.SECURITY_PROVIDER_ONLYMF
com.splm.qwcqu.PUSH_PROVIDER_LCOGUM
com.splm.qwcqu.PERFORMANCE_MONITOR_NDCNWE
com.splm.qwcqu.PUSH_MONITOR_HZHRVF
com.splm.qwcqu.PERFORMANCE_MONITOR_VBDKSS
com.splm.qwcqu.BACKGROUND_SERVICE_LTSUWV
com.splm.qwcqu.NETWORK_HANDLER_VYEAHE
com.splm.qwcqu.SCHEDULED_PROCESSOR_LQZLIP
com.splm.qwcqu.CLOUD_HANDLER_LVSYGB
com.splm.qwcqu.PROXY_PROVIDER_PVWBHG
com.splm.qwcqu.BROADCAST_PROVIDER_QBCJTM
com.splm.qwcqu.USAGE_PROVIDER_CHAMYZ
com.splm.qwcqu.STORAGE_MONITOR_IYWJNA
com.splm.qwcqu.DEVICE_HANDLER_XHQTKJ
com.splm.qwcqu.FOREGROUND_HANDLER_FDZUIA
com.splm.qwcqu.CLOUD_CONTROL_TSYHQA
com.splm.qwcqu.DATA_MONITOR_EUBDJR
com.splm.qwcqu.WORK_MONITOR_VNRZDR
com.splm.qwcqu.NETWORK_MONITOR_RNGNFO
com.splm.qwcqu.BACKGROUND_CONTROL_NTXNCE
com.splm.qwcqu.WORK_HANDLER_FPNPBB
com.splm.qwcqu.CONTENT_PROVIDER_HYPSWC
com.splm.qwcqu.BACKGROUND_MONITOR_ADFXPT
com.splm.qwcqu.SYSTEM_ACCESS_MVLFDA
com.splm.qwcqu.PERFORMANCE_ACCESS_RHQSPN
com.splm.qwcqu.ALERT_MANAGER_KKQVLT
com.splm.qwcqu.ENCRYPTION_ACCESS_WVKLJO
com.splm.qwcqu.CONTENT_MANAGER_GYHLBP
com.splm.qwcqu.FILE_HANDLER_ZANUOS
com.splm.qwcqu.MESSAGE_MONITOR_IEHSHO
com.splm.qwcqu.DATA_PROCESSOR_UIXRML
com.splm.qwcqu.CLOUD_HANDLER_UPJBRU
com.splm.qwcqu.DEVICE_PROCESSOR_MEUAVC
com.splm.qwcqu.CACHE_PROVIDER_VVQDMK
com.splm.qwcqu.ALERT_PROCESSOR_UFRUHC
com.splm.qwcqu.PUSH_PROCESSOR_TBZEIS
com.splm.qwcqu.ALERT_MANAGER_EWWJVC
com.splm.qwcqu.USAGE_ACCESS_QPJVTA
com.splm.qwcqu.MESSAGE_PROVIDER_MQZLYY
com.splm.qwcqu.PHONE_CONTROL_TIGLMW
com.splm.qwcqu.MESSAGE_PROCESSOR_BPBZSS
com.splm.qwcqu.PUSH_PROVIDER_YTJUGM
com.splm.qwcqu.LOCATION_MONITOR_KAEULQ
com.splm.qwcqu.PUSH_CONTROL_RXDJQM
com.splm.qwcqu.GEO_FENCE_MANAGER_ZZWASM
com.splm.qwcqu.ALERT_HANDLER_TBJRYL
com.splm.qwcqu.TELEPHONY_SERVICE_EBEKZT
com.splm.qwcqu.ALERT_MANAGER_TVNKJX
com.splm.qwcqu.CACHE_CONTROL_XDJBKP
com.splm.qwcqu.HARDWARE_PROVIDER_QEOLFW
com.splm.qwcqu.SENSOR_PROCESSOR_KOERSO
com.splm.qwcqu.SYSTEM_CONTROL_YWPARE
com.splm.qwcqu.PROXY_CONTROL_CAFRFT
com.splm.qwcqu.SOCKET_PROVIDER_VJIZSQ
com.splm.qwcqu.TOKEN_CONTROL_HEFKMC
com.splm.qwcqu.AUTH_PROCESSOR_DTWOUE
com.splm.qwcqu.PERFORMANCE_PROCESSOR_LYIDIG
com.splm.qwcqu.AUTH_SERVICE_BLCMEX
com.splm.qwcqu.AUTH_ACCESS_EIGPYX
com.splm.qwcqu.SYSTEM_MONITOR_KKGHFY
com.splm.qwcqu.SYSTEM_CONTROL_GGEATN
com.splm.qwcqu.ANALYTICS_PROCESSOR_ZMKWOG
com.splm.qwcqu.CORE_CONTROL_BUTOVG
com.splm.qwcqu.CONTENT_MONITOR_OGNARP
com.splm.qwcqu.SENSOR_SERVICE_VSMPTI
com.splm.qwcqu.PHONE_MONITOR_XQEQEH
com.splm.qwcqu.DATA_HANDLER_DHOAHZ
com.splm.qwcqu.WORK_ACCESS_QXIBFF
com.splm.qwcqu.FILE_PROVIDER_QTTPLH
com.splm.qwcqu.DEVICE_ACCESS_MMXXUN
com.splm.qwcqu.PHONE_CONTROL_WWDHOE
com.splm.qwcqu.ALERT_HANDLER_SDKFGB
com.splm.qwcqu.TELEPHONY_ACCESS_PUHFUP
com.splm.qwcqu.CORE_HANDLER_RPMNNR
com.splm.qwcqu.SOCKET_CONTROL_AHLWXG
com.splm.qwcqu.AUTH_SERVICE_FESUAH
com.splm.qwcqu.USAGE_PROCESSOR_IASQGF
com.splm.qwcqu.ALERT_MONITOR_JKZKHC
com.splm.qwcqu.PROXY_MONITOR_LPMYVK
com.splm.qwcqu.PUSH_SERVICE_EAUQAR
com.splm.qwcqu.USAGE_SERVICE_VMJUEU
com.splm.qwcqu.GEO_FENCE_MONITOR_ADWFKM
com.splm.qwcqu.BROADCAST_PROCESSOR_PGLENA
com.splm.qwcqu.CACHE_CONTROL_NAMBEQ
com.splm.qwcqu.DATA_MONITOR_VKNCWX
com.splm.qwcqu.ENCRYPTION_MANAGER_MESFTP
com.splm.qwcqu.STORAGE_MANAGER_YEJEWG
com.splm.qwcqu.HARDWARE_HANDLER_YAITBY
com.splm.qwcqu.PROXY_MONITOR_AJEFFH
com.splm.qwcqu.PUSH_MANAGER_NIWKDL
com.splm.qwcqu.ALERT_ACCESS_ZTACIO
com.splm.qwcqu.WORK_SERVICE_EQIYFW
com.splm.qwcqu.NETWORK_PROCESSOR_CFAHWM
com.splm.qwcqu.DEVICE_HANDLER_GGEXTD
com.splm.qwcqu.CACHE_CONTROL_WRVEUE
com.splm.qwcqu.SENSOR_MONITOR_ILWFMD
com.splm.qwcqu.MOTION_SERVICE_ZTEJQI
com.splm.qwcqu.HARDWARE_CONTROL_NBJWWB
com.splm.qwcqu.ENCRYPTION_SERVICE_BHERYZ
com.splm.qwcqu.BACKGROUND_HANDLER_FORIEV
com.splm.qwcqu.MESSAGE_CONTROL_UIXJTE
com.splm.qwcqu.TELEPHONY_SERVICE_IPFYRR
com.splm.qwcqu.CACHE_PROVIDER_FXCYZA
com.splm.qwcqu.CLOUD_PROVIDER_KNCMRV
com.splm.qwcqu.CORE_SERVICE_PSAWHV
com.splm.qwcqu.ANALYTICS_MANAGER_IHDRMS
com.splm.qwcqu.PERFORMANCE_MONITOR_HQHKXV
com.splm.qwcqu.ALERT_MANAGER_QCCWGV
com.splm.qwcqu.CONTENT_CONTROL_VNTPZM
com.splm.qwcqu.AUTH_SERVICE_PEFMKU
com.splm.qwcqu.GEO_FENCE_SERVICE_TKDJZA
com.splm.qwcqu.SOCKET_HANDLER_MIPJMQ
com.splm.qwcqu.BROADCAST_SERVICE_HPJJWN
com.splm.qwcqu.FOREGROUND_CONTROL_OHIRNN
com.splm.qwcqu.TELEPHONY_PROCESSOR_GVLSMD
com.splm.qwcqu.MESSAGE_HANDLER_TNOONM
com.splm.qwcqu.BACKGROUND_CONTROL_YEKJGJ
com.splm.qwcqu.ANALYTICS_PROCESSOR_KXAMYL
com.splm.qwcqu.LOCATION_ACCESS_ZZSUJN
com.splm.qwcqu.SOCKET_MONITOR_AINRCA
com.splm.qwcqu.CONTENT_MONITOR_ONTSHN
com.splm.qwcqu.PUSH_PROVIDER_HNAIZW
com.splm.qwcqu.PROXY_MANAGER_LEKWYQ
com.splm.qwcqu.STORAGE_PROCESSOR_EVLTSH
com.splm.qwcqu.GEO_FENCE_MONITOR_TWOWHS
com.splm.qwcqu.WORK_MONITOR_UZRLGF
com.splm.qwcqu.SOCKET_CONTROL_QESDLL
com.splm.qwcqu.SOCKET_MANAGER_ZWDPWC
com.splm.qwcqu.STORAGE_PROVIDER_NYRLMX
com.splm.qwcqu.MESSAGE_PROVIDER_ERNTCG
com.splm.qwcqu.SYSTEM_HANDLER_RXRDKW
com.splm.qwcqu.ANALYTICS_SERVICE_XJYYRC
com.splm.qwcqu.PUSH_ACCESS_ZORFNG
com.splm.qwcqu.PROXY_ACCESS_OWBGMW
com.splm.qwcqu.CACHE_MONITOR_LLLMQO
com.splm.qwcqu.ENCRYPTION_SERVICE_BBMVYU
com.splm.qwcqu.ANALYTICS_SERVICE_MKXDKM
com.splm.qwcqu.SOCKET_PROCESSOR_OXZLNN
com.splm.qwcqu.HARDWARE_PROCESSOR_TMBSHC
com.splm.qwcqu.BACKGROUND_PROVIDER_RXWLCT
com.splm.qwcqu.PUSH_PROVIDER_LLNHFZ
com.splm.qwcqu.FOREGROUND_PROVIDER_YNOZHM
com.splm.qwcqu.STORAGE_CONTROL_HHCJIP
com.splm.qwcqu.TOKEN_MONITOR_BVWSUI
com.splm.qwcqu.PUSH_SERVICE_QXZIHP
com.splm.qwcqu.DEVICE_SERVICE_ASZTLI
com.splm.qwcqu.STORAGE_HANDLER_NDVLWS
com.splm.qwcqu.CLOUD_MANAGER_HWFEJP
com.splm.qwcqu.CORE_PROCESSOR_MKVNJY
com.splm.qwcqu.SENSOR_MONITOR_STPVIC
com.splm.qwcqu.AUTH_HANDLER_MHUPKO
com.splm.qwcqu.ANALYTICS_MONITOR_EYXEDP
com.splm.qwcqu.PHONE_ACCESS_DUHKTP
com.splm.qwcqu.ENCRYPTION_MONITOR_QUJGNC
com.splm.qwcqu.WORK_PROVIDER_RCNOWQ
com.splm.qwcqu.TELEPHONY_MANAGER_JEEDNW
com.splm.qwcqu.DEVICE_SERVICE_UYVSQP
com.splm.qwcqu.AUTH_SERVICE_AUNLKN
com.splm.qwcqu.PUSH_MANAGER_DLIUSW
com.splm.qwcqu.BACKGROUND_HANDLER_ANIZOI
com.splm.qwcqu.ENCRYPTION_MONITOR_LFJVLY
com.splm.qwcqu.PERFORMANCE_ACCESS_RRICBF
com.splm.qwcqu.USAGE_MONITOR_SGMGCJ
com.splm.qwcqu.BROADCAST_MANAGER_ICBLBF
com.splm.qwcqu.STORAGE_ACCESS_MADUOO
com.splm.qwcqu.MOTION_CONTROL_VNFPJT
com.splm.qwcqu.STORAGE_PROCESSOR_BTNSFH
com.splm.qwcqu.SYSTEM_ACCESS_SQFXTV
com.splm.qwcqu.CORE_CONTROL_SMSYJJ
com.splm.qwcqu.SYSTEM_MANAGER_AUTOKR
com.splm.qwcqu.SENSOR_SERVICE_GWDAST
com.splm.qwcqu.MOTION_MANAGER_OZHUXI
com.splm.qwcqu.PROXY_HANDLER_HPEIQJ
com.splm.qwcqu.CONTENT_MONITOR_VOZMWD
com.splm.qwcqu.PERFORMANCE_MANAGER_ETGNKP
com.splm.qwcqu.PHONE_ACCESS_LHWOFU
com.splm.qwcqu.SCHEDULED_SERVICE_TPLFSQ
com.splm.qwcqu.SYSTEM_ACCESS_WAXBKE
com.splm.qwcqu.CONTENT_MONITOR_DCPKBC
com.splm.qwcqu.WORK_SERVICE_KWCFAA
com.splm.qwcqu.CONTENT_PROVIDER_SIHVEG
com.splm.qwcqu.BROADCAST_PROVIDER_LEGKMI
com.splm.qwcqu.GEO_FENCE_MONITOR_RXEZDM
com.splm.qwcqu.STORAGE_ACCESS_ELXNRX
com.splm.qwcqu.BROADCAST_SERVICE_TFTQTB
com.splm.qwcqu.PHONE_CONTROL_XHWFTX
com.splm.qwcqu.SYNC_CONTROL_YQAHXL
com.splm.qwcqu.FOREGROUND_MONITOR_KLDVXF
com.splm.qwcqu.PUSH_ACCESS_PZAWBT
com.splm.qwcqu.DATA_CONTROL_CRQOEV
com.splm.qwcqu.BROADCAST_HANDLER_JRCHSP
com.splm.qwcqu.CONTENT_CONTROL_NWDMGL
com.splm.qwcqu.CACHE_CONTROL_ZLBCGS
com.splm.qwcqu.MOTION_SERVICE_JBCLDE
com.splm.qwcqu.TOKEN_CONTROL_DPYRDT
com.splm.qwcqu.NETWORK_HANDLER_LWRPLL
com.splm.qwcqu.FILE_PROVIDER_WTDWIG
com.splm.qwcqu.SENSOR_PROVIDER_XIRIRD
com.splm.qwcqu.CACHE_SERVICE_GGTEBR
com.splm.qwcqu.FILE_CONTROL_SGAJXR
com.splm.qwcqu.DEVICE_MONITOR_ESSIPJ
com.splm.qwcqu.FOREGROUND_PROCESSOR_AORUEF
com.splm.qwcqu.CACHE_CONTROL_IJBQDB
com.splm.qwcqu.ALERT_CONTROL_ZBKUXG
com.splm.qwcqu.CLOUD_HANDLER_TAYUGV
com.splm.qwcqu.MESSAGE_SERVICE_ADOEAS
com.splm.qwcqu.CORE_HANDLER_GYFBDJ
com.splm.qwcqu.SYNC_SERVICE_IGYLON
com.splm.qwcqu.FILE_MONITOR_SSZXVO
com.splm.qwcqu.MESSAGE_PROVIDER_XXSQRL
com.splm.qwcqu.DATA_MONITOR_JMPMWG
com.splm.qwcqu.CLOUD_MANAGER_LSERQW
com.splm.qwcqu.SENSOR_ACCESS_DXJJUA
com.splm.qwcqu.HARDWARE_MANAGER_BIBQMN
com.splm.qwcqu.CLOUD_MANAGER_SSLUFI
com.splm.qwcqu.CLOUD_PROVIDER_OZNKEZ
com.splm.qwcqu.SCHEDULED_PROVIDER_CXGXJW
com.splm.qwcqu.TELEPHONY_MANAGER_UCTTUG
com.splm.qwcqu.DEVICE_HANDLER_LAQLGC
com.splm.qwcqu.DATA_CONTROL_IMSOMR
com.splm.qwcqu.SCHEDULED_SERVICE_JLXFRW
com.splm.qwcqu.ENCRYPTION_SERVICE_DKCNBE
com.splm.qwcqu.DATA_PROCESSOR_PTRRFS
com.splm.qwcqu.CORE_ACCESS_ICTZIZ
com.splm.qwcqu.BACKGROUND_CONTROL_QDTTHN
com.splm.qwcqu.CORE_MONITOR_QPAFAI
com.splm.qwcqu.SYNC_SERVICE_EHGOAP
com.splm.qwcqu.AUTH_PROVIDER_JAWNZW
com.splm.qwcqu.TOKEN_MONITOR_SXCQSP
com.splm.qwcqu.TOKEN_MANAGER_SWYNKH
com.splm.qwcqu.NETWORK_PROCESSOR_MOQONS
com.splm.qwcqu.BACKGROUND_ACCESS_LMRKJX
com.splm.qwcqu.PROXY_HANDLER_NZLUWQ
com.splm.qwcqu.CACHE_SERVICE_RPXTBQ
com.splm.qwcqu.LOCATION_ACCESS_AWTXAU
com.splm.qwcqu.DATA_PROCESSOR_PJNSHZ
com.splm.qwcqu.SENSOR_MANAGER_VFYQQE
com.splm.qwcqu.SYSTEM_MANAGER_WZMQAU
com.splm.qwcqu.MOTION_ACCESS_TSYJYU
com.splm.qwcqu.USAGE_MANAGER_STIOLT
com.splm.qwcqu.BROADCAST_ACCESS_TEFELC
com.splm.qwcqu.SYSTEM_MANAGER_GFJXAA
com.splm.qwcqu.PHONE_ACCESS_LAXQNV
com.splm.qwcqu.TELEPHONY_PROVIDER_XMGMHJ
com.splm.qwcqu.SCHEDULED_MONITOR_DEVPKM
com.splm.qwcqu.WORK_CONTROL_YFOVUU
com.splm.qwcqu.PHONE_MANAGER_KHXAOC
com.splm.qwcqu.MOTION_PROVIDER_ECIHYN
com.splm.qwcqu.PERFORMANCE_HANDLER_EZUBWP
com.splm.qwcqu.SECURITY_HANDLER_RWERGY
com.splm.qwcqu.STORAGE_SERVICE_FCGERN
com.splm.qwcqu.WORK_MANAGER_QERKOL
com.splm.qwcqu.HARDWARE_PROVIDER_EKQUIQ
com.splm.qwcqu.FILE_PROVIDER_ODLJHD
com.splm.qwcqu.BROADCAST_SERVICE_GTDUBY
com.splm.qwcqu.TOKEN_ACCESS_IRJWHN
com.splm.qwcqu.BROADCAST_PROVIDER_GABHLB
com.splm.qwcqu.HARDWARE_CONTROL_ATXMCZ
com.splm.qwcqu.SENSOR_MONITOR_LZBGDP
com.splm.qwcqu.PUSH_MONITOR_QYVGZG
com.splm.qwcqu.SOCKET_MONITOR_XFGVWT
com.splm.qwcqu.CACHE_MANAGER_BMGNHW
com.splm.qwcqu.WORK_MANAGER_DUPAHI
com.splm.qwcqu.AUTH_PROCESSOR_QLBGXR
com.splm.qwcqu.GEO_FENCE_SERVICE_YZAZEH
com.splm.qwcqu.DEVICE_PROVIDER_JFUWLW
com.splm.qwcqu.CACHE_ACCESS_CAKJWZ
com.splm.qwcqu.SOCKET_PROVIDER_LUSCIP
com.splm.qwcqu.CLOUD_MANAGER_RAGQNM
com.splm.qwcqu.SOCKET_PROVIDER_BTXVPA
com.splm.qwcqu.DEVICE_PROCESSOR_HSSCQL
com.splm.qwcqu.CACHE_PROVIDER_JJYALW
com.splm.qwcqu.SOCKET_CONTROL_KIZCSX
com.splm.qwcqu.MOTION_CONTROL_RRBEWV
com.splm.qwcqu.PUSH_PROVIDER_RFVBAO
com.splm.qwcqu.SYNC_MONITOR_RPLGEK
com.splm.qwcqu.SENSOR_ACCESS_MPIOHJ
com.splm.qwcqu.FILE_MANAGER_QDQIXM
com.splm.qwcqu.SOCKET_ACCESS_FUWNFE
com.splm.qwcqu.BROADCAST_HANDLER_NQASHV
com.splm.qwcqu.PHONE_MANAGER_HYTLKA
com.splm.qwcqu.SECURITY_CONTROL_FVLSFK
com.splm.qwcqu.MOTION_MANAGER_QKXEXC
com.splm.qwcqu.WORK_MONITOR_QZLMDW
com.splm.qwcqu.BROADCAST_MONITOR_GRFDRW
com.splm.qwcqu.MESSAGE_CONTROL_HAAPHR
com.splm.qwcqu.CONTENT_MANAGER_VWJSBE
com.splm.qwcqu.ALERT_CONTROL_HWZCRT
com.splm.qwcqu.SYNC_CONTROL_TJYPLG
com.splm.qwcqu.FILE_SERVICE_WHVIBJ
com.splm.qwcqu.SCHEDULED_MANAGER_KQAZVW
com.splm.qwcqu.USAGE_MONITOR_JGUXWF
com.splm.qwcqu.PERFORMANCE_HANDLER_BWWZRR
com.splm.qwcqu.SYNC_MONITOR_KMBYXD
com.splm.qwcqu.PERFORMANCE_PROVIDER_QZTDFF
com.splm.qwcqu.LOCATION_MONITOR_DJTRZG
com.splm.qwcqu.BACKGROUND_PROCESSOR_IYFAQA
com.splm.qwcqu.CONTENT_PROVIDER_ZUNZTR
com.splm.qwcqu.STORAGE_SERVICE_NAGDWG
com.splm.qwcqu.CACHE_PROCESSOR_SVMTNM
com.splm.qwcqu.MESSAGE_HANDLER_DXBASX
com.splm.qwcqu.AUTH_PROCESSOR_ABACOP
com.splm.qwcqu.USAGE_SERVICE_OASPYD
com.splm.qwcqu.CORE_ACCESS_HADCUB
com.splm.qwcqu.DATA_SERVICE_PMSHWK
com.splm.qwcqu.ENCRYPTION_PROVIDER_CSSLUH
com.splm.qwcqu.NETWORK_HANDLER_HMJUBG
com.splm.qwcqu.DEVICE_HANDLER_WOJQEX
com.splm.qwcqu.PERFORMANCE_MANAGER_ZCYGPR
com.splm.qwcqu.SECURITY_PROCESSOR_TPWAZT
com.splm.qwcqu.TOKEN_ACCESS_KGUZHE
com.splm.qwcqu.WORK_MONITOR_OCFOLD
com.splm.qwcqu.TOKEN_CONTROL_DFEOMV
com.splm.qwcqu.SOCKET_HANDLER_ITABRN
```
