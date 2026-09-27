---
name: mobile
description: Mobile application security assessment covering Android (APK) and iOS (IPA) binaries, Frida dynamic instrumentation, certificate pinning bypass, insecure data storage, and OWASP MASVS v2.0 verification.
domain: cybersecurity
subdomain: mobile-security
tags: [mobile, android, ios, apk, ipa, frida, masvs, objection, certificate-pinning, jadx]
mitre_attack: [T1404, T1407, T1417, T1426, T1437]
d3fend_techniques: [D3-APP, D3-OBF, D3-RDT]
version: "1.0"
---

# Mobile Application Security Skill

Assessment of client-side mobile applications (Android & iOS) and their communication channels adhering to **OWASP Mobile Application Security Verification Standard (MASVS v2.0)**.

## Tooling Matrix

| Tool | Purpose | Standard Execution | Fallback |
| :--- | :--- | :--- | :--- |
| `jadx` | Android DEX to Java decompiler | `jadx -d out/ target.apk` | `apktool` / `baksmali` |
| `MobSF` | Automated mobile security framework | `mobsf -f target.apk` | Manual static checklist |
| `Frida` | Dynamic binary instrumentation toolkit | `frida -U -f <APP_ID> -l hook.js` | `objection` command line |
| `objection` | Runtime mobile exploration | `objection --gadget <APP> explore` | Manual Frida script injection |

## Methodology

### 1. Static Application Security Testing (SAST)
- **Manifest & IPC Analysis (Android)**: Inspect `AndroidManifest.xml` for exported activities, broadcast receivers, content providers, and services. Test for intent injection and unauthorized component access.
- **Entitlements & Permissions (iOS)**: Inspect `Info.plist` and provision profiles for excessive entitlements and insecure URL schemes.
- **Hardcoded Secrets & API Keys**: Scan decompiled bytecode for hardcoded JWTs, private keys, AWS credentials, and staging URLs.

### 2. Network Security & Certificate Pinning (MASVS-NETWORK)
- Verify enforcement of TLS and Network Security Configuration (`cleartextTrafficPermitted="false"`).
- Test dynamic bypass of SSL/TLS certificate pinning using Frida scripts (e.g., universal SSL pinning bypass hooks).
- Inspect proxied HTTP/WebSocket communication for unauthenticated backend endpoints.

### 3. Local Data Storage & Cryptography (MASVS-STORAGE, MASVS-CRYPTO)
- Inspect SharedPreferences, SQLite databases, Realm, and local caches for unencrypted PII, tokens, or session identifiers.
- On iOS, verify sensitive data storage in the Keychain with appropriate accessibility attributes (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`).
- Detect weak cryptography (DES, RC4, MD5, static initialization vectors, ECB mode).

### 4. Dynamic Runtime & Tampering Resiliency (MASVS-RESILIENCE)
- Test root / jailbreak detection effectiveness under Frida runtime hooks.
- Test debuggability flags (`android:debuggable="true"`) and emulator detection bypasses.

## Output
- MASVS v2.0 compliance matrix and client-side vulnerability findings.
- Structured findings formatted per [`schemas/finding.md`](../../schemas/finding.md).
