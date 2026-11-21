# Methodology: mobile

Source: [PentestingEverything/Mobile Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/Mobile%20Pentesting)

---

# Mobile Application Pentesting

This project focuses on penetration testing methodologies and tools for mobile applications. It covers security assessment techniques for both Android and iOS platforms.

## Core Concepts

Mobile application pentesting assesses the security of an app, its on-device data, and its communication with backend services. Because the binary runs on a device the user (and attacker) fully controls, the goal is to find what trust the app misplaces in the client side.

**Methodology / Phases:**
- Recon and setup: obtain the build (APK/IPA), prepare a rooted/jailbroken device or emulator, and proxy traffic.
- Static analysis: decompile and review code, manifests, and resources for secrets, weak crypto, and exported components.
- Dynamic analysis: run the app, hook and instrument it (Frida/Objection), and observe runtime behavior.
- Network analysis: intercept API traffic and test for weak TLS, certificate pinning bypass, and insecure data in transit.
- Local storage review: inspect databases, preferences, keychain/keystore, logs, and cache for sensitive data.

**Key Concepts / What to look for:**
- Insecure data storage: credentials, tokens, or PII written in cleartext to device storage.
- Weak transport security: missing TLS validation or pinning that allows interception.
- Hardcoded secrets and weak cryptography embedded in the binary.
- Insecure platform usage: exported activities/services, intent issues, and improper permissions.
- Client-side trust: logic, authorization, or paywall checks enforced only on the device.

### Please Navigate for dedicated Android and iOS resources

 | S.N | Topic                                    | Link |
|-----|------------------------------------------|------|
| 1 | Android      | [Click here for Android Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/Mobile%20Pentesting/Android%20Pentesting) |
| 2 | iOS          | [Click here for iOS Pentesting](https://github.com/m14r41/PentestingEverything/tree/main/Mobile%20Pentesting/iOS%20Pentesting) |
| 2 | Android and iOS          | [Interview Questions also cover a lot](https://github.com/m14r41/CyberSecurity-Interview/blob/main/Interview-Level-2.md) |

### Prerequisites

- Basic understanding of security principles and mobile app architectures.
- Knowledge of Android and iOS platforms.
- Necessary tools and frameworks installed (see Tools section below).

### Common Tests

1. **Static Analysis**: Review source code and app binaries fo

---

## Sub-Topics

- Android Pentesting
- iOS Pentesting

