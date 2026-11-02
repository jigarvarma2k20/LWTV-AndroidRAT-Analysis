# LWTV — Android RAT Analysis

Analysis of `LWTV_com.yunyou.control.dev_v274.533.185.apk` (`com.yunyou.control.dev`, label **LWTV**, brand **云游控制 / "Yunyou Control"**) — a China-built, India-targeted Android Remote Access Trojan with UPI/OTP theft, lock-screen credential harvesting, and full remote screen control.

![Platform](https://img.shields.io/badge/platform-Android-green)
![Type](https://img.shields.io/badge/type-RAT%20%2F%20Stalkerware-red)
![Status](https://img.shields.io/badge/status-actively%20operated-critical)
![Target](https://img.shields.io/badge/target-India-orange)
![Origin](https://img.shields.io/badge/author%20locale-Chinese-blue)

---

## Disclaimer

Published for defensive security research, threat intelligence, and education only. This documents live malware behaviour to help defenders detect and remediate it. Do not use any of this to build, deploy, or operate malware. The live sample is provided password-protected (`malware_artifacts.7z`, password `infected`) purely for analyst reproducibility — handle only in an isolated environment.

---

## Overview

`LWTV` is not a TV app. It is an Android RAT built around the Accessibility Service. The shipped APK is only a packed loader (26 KB DEX); the real 9.95 MB payload is AES-GCM encrypted inside `assets/VOUALmvLXIYX` and loaded in memory at startup via `InMemoryDexClassLoader` after hijacking the `Application` class.

Once running, an operator can:

| Capability | Details |
|---|---|
| Remote screen viewing | Periodic JPEG frames + full accessibility UI-tree dumps |
| Remote control | Tap / swipe / long-press / drag, text injection, open apps, keyguard unlock |
| Credential theft | Reconstructs lock-screen PIN & swipe pattern; fake biometric "Identity Verification" prompt |
| UPI / banking fraud | Targets Google Pay India, PhonePe, Paytm, BHIM/NPCI UPI, Amazon, WhatsApp |
| SMS / OTP theft | Dumps SMS inbox + exfiltrates new inbound SMS in real time |
| App inventory exfil | Full installed-app list with icons |
| Anti-uninstall | Blocks Settings, app list, accessibility settings, factory reset; fake OEM overlays |
| Persistence | Boot receivers, foreground service + wakelocks, exact alarms, anti-Doze keepalive |
| Fake "system update" cover | Full-screen fake update/fingerprint overlay hides the fraud running in the background |

C2: `https://www.capebej.com` (decoy `https://famelack.com/`) over WSS + MQTT5 fallback, pinned RSA-2048 server key, per-device P-256 key. Push-wake via Firebase (`whh6666-fcm`). Hardcoded auto-enrollment — no user action needed.

Not implemented: microphone, camera, GPS/location, contacts, call-log, clipboard read, shell, WebRTC.

### How the fraud looks to the victim

The phone shows a convincing **fake "system update"** (or fingerprint/face-verification) screen while the RAT works in the background: it unlocks the device by replaying the captured PIN/pattern, opens the banking/UPI app, injects taps and text, reads the SMS/OTP, and transfers funds — all hidden behind the overlay. The fake screen is a system-level window that sits over everything, dims the display, captures fingerprint touches, and hides itself from screenshots. This matches a reported real-world case in which a large sum was drained from a victim's bank account while the phone appeared to be updating.

---

## Sample Info

| File | Value |
|---|---|
| File | `LWTV_com.yunyou.control.dev_v274.533.185.apk` |
| Size | 6,158,481 bytes |
| APK SHA-256 | `056a8db666e4f154f9f6d0b7a00aa0703d2990ee2b1a085b7339a49bdef90495` |
| Decrypted payload SHA-256 | `cf6153e8e4b78cff0526df2d4580cbb48f816a460ec719808303c4e59927eb12` |
| Encrypted asset SHA-256 | `49c15345d5df2f97e2b1272fe759da554723bafef84e1e7c8a6b7115453f687e` |
| Package | `com.yunyou.control.dev` |
| Label / Brand | `LWTV` / `云游控制` ("Yunyou Control") |
| versionName | `274.533.185` (manifest) / payload `0.2.0` |
| minSdk / targetSdk | 28 / 34 |
| Built with | R8 8.2.2-dev, Kotlin + coroutines + OkHttp + Paho MQTT5 + Firebase |

### Second sample (dropper campaign, 2026-11-02)

A related build is distributed from `watchedlwfreelive.com` → AWS Lambda (Mumbai) → AWS S3 (`ap-south-1`). The downloaded APK is a **dropper** that shows a fake Google-Play "Installing…" screen and then installs the **same RAT** (`b.apk`, package `com.yunyou.control.dev`).

| Artifact | SHA-256 | Notes |
|---|---|---|
| `LW-TV.apk` | `e1c40c91be4265ff94fc56d931d1e7add46b00ada61d6c308e77acb84ca92c2a` | Dropper `com.dexjh.oan.jwwvgypi` |
| `b.apk` | `bf918302e5bac36fb849ed8a967cc91bcee691c2f9f7d284a20e489749a15b32` | Stage-2 RAT `com.yunyou.control.dev` |

---

## Infection & Loader Chain

The distributed APK is deliberately hostile to analysis:

- `AndroidManifest.xml` padded to 56 MB with the AXML `fileSize` field set to match; attribute names replaced with `UNKNOWN_SYSTEM_ATTRIBUTE_*`.
- 999 declared permissions — only 17 are real; the other 982 are fabricated (`com.splm.qwcqu.*`, inert) to bloat and confuse scanners.
- `classes.dex` is a 26 KB loader whose DEX header fields are scrambled (offsets up to ~4.8 billion in a 26 KB file) to break jadx/baksmali/apktool.

Loader flow (`com.wipjt.payvpkyvn.qczs.wfqq.QBCf3JUtW31HoXBzXWrLzqj9ufczaS`):

```
Application hijack -> read assets/VOUALmvLXIYX -> AES-GCM decrypt -> gunzip
-> InMemoryDexClassLoader (3 DEX cookies) -> run real RAT (com.yunyou.control.AgentApplication)
```

- Key derived at runtime by `recoverKey(String,String)`, implemented as a custom bytecode VM (8 state-machine classes, `v0..v9`) — anti-analysis control-flow virtualization.
- Payload runs entirely in memory; the loader never writes it to disk.

---

## Command & Control

### Hardcoded values (`BuildConfig`)

| Key | Value |
|---|---|
| C2 base URL | `https://www.capebej.com` |
| Decoy site | `https://famelack.com/` |
| FCM project | `whh6666-fcm` |
| FCM sender ID | `149789333529` |
| FCM API key | `AIzaSyAU78JJ5xN5gNrpNwSPk5KbnsrcLzRiuC8` |
| Auto-enrollment grant | `JLGBCY2qyEfkqUvqxaa6Mt7hp4buPY77nAZHlkjop2Q` (`ACCOUNT_BOUND_V1`) |
| Pinned server RSA-2048 SPKI | [see full report](./RAT_ANALYSIS_REPORT.md) |

### Protocol

- Endpoint discovery: `GET /m9eu/00/it2` returns a server-signed JWS manifest of C2 origins (rotates at runtime).
- Transports (one active): WSS `wss://{origin}/m9eu/00/d1` (preferred); MQTT5 `ssl://…` fallback, topics `yy/v1/device/{user}/session|/up|/down`.
- Auth: per-device P-256 key in AndroidKeyStore (`yunyou.installation.v1`) + `access_token`; server verified against the pinned RSA key.
- Sensitive commands carry a server-signed JWS lease fenced by `installation_id`/`connection_generation`/`recovery_epoch` (anti-replay).
- Push-wake: Firebase data message `type=RECONNECT` with a `wake_id` UUID — revives a dead channel; it carries no command.
- Obfuscated REST paths under `/m9eu/00/*`; TLS only, no payload-level encryption.

---

## Command Reception

No inbound connection to the device — the device dials out and the C2 pushes commands down the persistent channel.

1. Outbound connect -> fetch signed endpoint manifest -> authenticate -> open WSS (or MQTT).
2. Receive -> `openSocket$2$2.onMessage()` (size-check <=128 KB) -> `DeviceConnection.onMessage(JSONObject)` on a dedicated `HandlerThread`; MQTT via `Mqtt5DownstreamParser`.
3. Dispatch on the `"type"` field: `TAP, SWIPE, LONG_PRESS, DRAG, BACK, HOME, RECENTS, SCREEN_ON/OFF, VOLUME_*, MUTE, CLIPBOARD_SET, OPEN_URL, OPEN_APP, KEYGUARD_UNLOCK, NODE_ACTION, TEXT_REPLACE, SCREENSHOT, SEMANTIC, MATERIAL_DOWNLOAD, RESTART_AGENT, OEM_SETUP_GRANT`, …
4. FCM is only a wake beacon; bootstrap triggers are `LifecycleReceiver` (boot/quickboot/user-unlocked/package-replaced), `SmsReceiver`, and the 250 ms `ConnectionForegroundService.pulse()` loop.

---

## Capabilities

- Screen viewing: adaptive JPEG frames + compact UI-tree streaming (`UiSemantics`, `PixelAdaptiveController`, `SemanticFrameDedup`).
- Input injection: `dispatchGesture` (tap/swipe/long-press/drag), `TEXT_REPLACE`, `NODE_ACTION`, `LiveCoordinateInput` (`LIVE_COORDINATE_V1`).
- Credential theft: `MaskedFieldExtractor` + `CredentialCaptureSession` reconstruct PIN/pattern; `CredentialCaptureActivity` presents a fake "Identity Verification" prompt; `KeyguardUnlock*` replays the secret to unlock.
- UPI/banking: `GPaySniffer` narrows accessibility scope around `nbupaisa` / `phonepe` / `paytm` / `npci.upiapp` / `amazon` / `whatsapp` to harvest payment credentials & OTPs.
- SMS: full inbox dump + live `SMS_RECEIVED` exfil.
- App inventory: all launcher apps + icons.
- Not present: camera, mic, GPS, contacts, call log, clipboard read, shell, WebRTC.

---

## Notable Engineering

1. Geometric lock-screen credential reconstruction — tracks touched dots and digit buffers to rebuild the PIN and swipe pattern, then replays them via `dispatchGesture`. A purpose-built keyguard-bypass engine.
2. Fake OEM system-update / biometric overlay in ~20 languages — impersonates the device's own brand (Samsung, Xiaomi/Redmi/POCO, Huawei, HONOR, OPPO, vivo, realme, OnePlus, Motorola, Nokia, Infinix, Tecno, itel, ASUS, Lenovo, MEIZU, Nothing, Google) with localized "system update / fingerprint / face verification" text, and harvests the secret the victim types. It is a fullscreen **system-level** window that dims the display (2–8% brightness), listens to the fingerprint sensor, and hides itself from screenshots — used as a live cover while the fraud runs in the background. A second WebView-based injector overlays fake login/payment pages on top of real banking/UPI apps.
3. UI-tree semantic streaming — the operator drives the device by UI-element semantics, not just raw coordinates.
4. Localized, layout-aware anti-removal — `AppProtector` recognizes the actual Settings screens of ~20 OEMs and blocks `Force stop` / `Uninstall` / `Disable` / `Clear data` / `Factory reset` in many languages.
5. Replay-proof signed command leases — generation/epoch-fenced JWS, unusual for Android malware.
6. Enrollment-as-a-service licensing — hardcoded `ACCOUNT_BOUND_V1` grant with seat quota and per-deployment APK updates.
7. ~30-class keepalive/recovery state machine — survives Doze, OEM killers, and self-restart.
8. Persistence automation that drives OEM UI — navigates per-OEM/per-locale Settings to silently grant itself auto-start and battery exemptions.
9. No anti-RE / anti-Frida / root detection in the payload — protection lives in the packer and manifest.

---

## Attribution: China -> India

| Claim | Confidence |
|---|---|
| Chinese-language product (`云游控制`, Simplified Chinese operator UI) | High |
| Built/operated by Chinese-speaking developers | High |
| Targets India (UPI/payment apps, English-locale gating, Indian SIM handling) | High |
| Specific group / nation-state | Not established |

Why India (code-backed):
- UPI/Indian payment apps named explicitly: Google Pay India, PhonePe, Paytm, BHIM/NPCI, Amazon-India, WhatsApp (`GPaySniffer`).
- SIM PIN/PUK capture (Indian carriers enforce default SIM PIN).
- Persistence automation gated on English-locale devices (`Locale.getLanguage() == "en"`), with English + Chinese language packs.

Why China (developer side):
- Product branding `云游控制`; all operator strings Simplified Chinese (enrollment/licensing references `管理员` = "administrator").
- Package `com.yunyou.control`, loader namespace `com.wipjt.*`, FCM `whh6666-fcm`, bilingual dev string `开发测试设备 / DEV TEST DEVICE`.

The asymmetry is the signal: a Chinese operator product pointed at Indian victims, built by Chinese-speaking developers for India banking/UPI fraud. Attribute by infrastructure and TTPs, not language alone.

---

## Indicators of Compromise

### Files / hashes

```
056a8db666e4f154f9f6d0b7a00aa0703d2990ee2b1a085b7339a49bdef90495  APK
cf6153e8e4b78cff0526df2d4580cbb48f816a460ec719808303c4e59927eb12  decrypted payload DEX
49c15345d5df2f97e2b1272fe759da554723bafef84e1e7c8a6b7115453f687e  assets/VOUALmvLXIYX
```

### Network

```
213.111.157.6          # C2 (www.capebej.com) - Trunk Networks AS43180, Seychelles-registered
www.capebej.com        # C2 base, paths /m9eu/00/*
capebej.com
famelack.com           # decoy site
whh6666-fcm            # Firebase project (sender 149789333529)
yy/v1/device/{user}/session|/up|/down   # MQTT topics
watchedlwfreelive.com                              # fake LWTV distribution page
5ewupcxyoz7bkics25pp7nq36e0davfa.lambda-url.ap-south-1.on.aws   # APK redirect (Lambda, Mumbai)
an0opchi4607663.s3.ap-south-1.amazonaws.com        # APK storage (S3 ap-south-1)
```

### On-device

- Package `com.yunyou.control.dev`, label `LWTV`
- Accessibility service `com.yunyou.control.AssistanceAccessibilityService`
- Files: `noBackupFilesDir/installation.json`, `noBackupFilesDir/fcm-token`, `shared_prefs/keepalive_alarm_plan.xml`, `shared_prefs/ic_store.xml`
- AndroidKeyStore alias `yunyou.installation.v1`

### Code

- Loader package `com.wipjt.payvpkyvn.qczs.wfqq`
- Payload package `com.yunyou.control`

---

## Remediation

If found on a device (India campaign — prioritize financial/PII response):

1. Treat the device as fully compromised — factory reset is the only trustworthy fix (the app actively blocks uninstall/reset).
2. Immediately secure banking and UPI: change online-banking and UPI passwords, reset the UPI PIN in the bank app, re-verify registered devices.
3. Rotate all passwords entered on the device (email, WhatsApp, Google, social).
4. Change the screen-lock PIN/pattern and the SIM PIN/PUK (contact the carrier); re-bind biometrics.
5. Assume all inbound SMS (including bank OTPs) leaked; notify SMS/OTP-dependent services.
6. Block at the perimeter:

   ```
   213.111.157.6
   www.capebej.com
   capebej.com
   famelack.com
   ```

   and the Firebase project `whh6666-fcm` / sender `149789333529`.
7. Report to your AV/IR vendor, Google Play Protect, and — for Indian victims — CERT-In / the bank fraud channel.

---

## Methodology

1. Static: `unzip`, entropy/hex analysis, `androguard`, `jadx`, custom DEX parser, `aapt2` badging.
2. Dynamic: isolated Android 33 emulator (google_apis, arm64, no Play Store) + `frida-server` 17.25.1. Launched the app, let the loader self-decrypt, then Frida-scanned process memory for `dex\n039` magic to recover the 9.95 MB payload DEX (1481 real classes).
3. Decompilation: `jadx` -> 3505 classes analyzed for C2, capabilities, and attribution.

---

## Repository Contents

| File | Description |
|---|---|
| `README.md` | This file |
| `RAT_ANALYSIS_REPORT.md` | Full detailed analysis report |
| `AndroidManifest.decoded.xml` | Decoded (effective) manifest |
| `AndroidManifest.dumpsys-full.txt` | Framework-parsed manifest dump |
| `LWTV.sha256.txt` | SHA-256 hashes of all artifacts |
| `malware_artifacts.7z` | Password-protected live malware (see below) |

### Malware samples

The live malware artifacts are stored in `malware_artifacts.7z`, which is password-protected and header-encrypted so that it is not runnable by accident, its contents are not indexed/flagged while at rest, and it cannot be listed without the password.

Password: `infected` (industry-standard convention for malware archives)

```bash
# Extract (do this ONLY in an isolated / air-gapped analysis VM)
7z x -pinfected malware_artifacts.7z

# Contents:
#   LWTV_com.yunyou.control.dev_v274.533.185.apk   (original distributed APK)
#   decrypted_payload.dex                          (9.95 MB decrypted RAT DEX)
#   extract/assets/VOUALmvLXIYX                    (AES-GCM encrypted payload asset)
#   LW-TV.apk                                      (dropper, com.dexjh.oan.jwwvgypi)
#   b.apk                                          (stage-2 RAT, com.yunyou.control.dev)
```

These are live malware. Extract and handle only inside a disposable, network-isolated analysis environment. Verify hashes against `LWTV.sha256.txt` before use. Do not execute.

---

## Research Notes

Independent malware analysis & reverse engineering. Feedback, corrections, and IOCs welcome via issues or PRs.

---

## License

Analysis and documentation released for defensive purposes. No license is granted to use the malware itself.
