# ⬢ qPGP

**An offline, post-quantum, minimal-permission vault for encrypting and decrypting sensitive messages on Android.**

qPGP is not a messenger. It has no network code and — more importantly — **no `INTERNET` permission**, so the Linux kernel itself refuses to give it a socket. It is a sealed room: you write a message, it comes out as armored ciphertext, and *you* choose how that ciphertext travels (paste it into any channel, show it as a QR, print it, carry it on paper). Decryption happens the same way, in reverse.

> ⚠ **This code has not undergone external cryptographic review. Do not bet lives on it until it has.** See [Honest residual risks](#honest-residual-risks-read-this).

---

## Install

**Recommended: [Obtainium](https://github.com/ImranR98/Obtainium)** — add this repository URL and it tracks releases automatically:

```
https://github.com/tobias606/qpgp
```

Or grab the APK directly from the [latest release](https://github.com/tobias606/qpgp/releases/latest) and install it. Releases are signed with a stable self-signed key, so updates install over the top. Android will warn about "unknown sources" — expected for a non-Play app.

### Strongly recommended: run it on [GrapheneOS](https://grapheneos.org)

qPGP's own threat model states plainly that **a compromised OS defeats every guarantee this app makes** — no application can protect plaintext from a kernel that is reading its memory, its framebuffer, and its keystrokes. So the single highest-leverage thing you can do for qPGP's security is run it on a hardened OS.

**GrapheneOS** (Pixel devices) is the recommended platform because it directly shrinks the residual risks listed below:

- **Hardened kernel & memory allocator** — shrinks the "compromised OS/kernel" risk that qPGP cannot address itself.
- **No Google Play Services by default** — fewer privileged processes with memory access; a smaller trusted computing base.
- **Strong hardware keystore / StrongBox on Pixels** — qPGP's at-rest layer and biometric unlock lean on this; GrapheneOS + Titan M2 is the best case for it.
- **Per-app network permission** — even though qPGP has no `INTERNET` permission at all, GrapheneOS lets you *prove* it by toggling network off system-wide for the app.
- **Duress / auto-reboot / "lockdown"** — complements qPGP's own duress PIN with OS-level protections (reboot-to-BFU wipes keys from RAM).
- **No third-party IME needed** — pair with a trusted keyboard (or GrapheneOS's) to shrink the IME-keylogging risk.

For the strongest posture: a **dedicated GrapheneOS device, never networked**, used only for qPGP. On a shared everyday phone qPGP still works and still helps, but you inherit that phone's full attack surface.

---

## Features

- **Hybrid post-quantum crypto** — see below.
- **Continuous key rotation** — every message advertises a fresh key; forward secrecy + post-compromise security per exchange.
- **QR identity exchange** — show/scan an animated multi-frame QR to add a contact without touching the clipboard or a network.
- **Manual paste exchange** — armored `-----BEGIN QPGP …-----` blocks work over any channel, with a one-tap copy button for outputs.
- **Contact management** — local alias, verification words, fingerprint, and delete-with-crypto-shred.
- **Biometric unlock (opt-in)** — open the vault with fingerprint/face instead of the passphrase.
- **Duress PIN (opt-in)** — a coercion PIN that destroys the real vault and opens a harmless dummy one, indistinguishably.
- **Destroy vault** — irreversible crypto-shredding of everything.
- **Zero background anything** — no telemetry, no analytics, no push, no services.

---

## Security architecture

### Cryptography — hybrid everything, no compromises

Breaking any qPGP message requires breaking **both** a NIST post-quantum primitive **and** a mature classical primitive:

| Purpose | Post-quantum | Classical | Combiner |
|---|---|---|---|
| Key encapsulation | **ML-KEM-1024** (FIPS 203, Kyber, Cat-5) | **X25519** (fresh ephemeral per message) | HKDF-SHA-512 over both shared secrets, salted with the recipient key hash |
| Signatures | **ML-DSA-87** (FIPS 204, Dilithium, Cat-5) | **Ed25519** | Dual signature — *both* must verify or the message is rejected |
| Message encryption | — | **ChaCha20-Poly1305** AEAD, fresh key per message | — |
| Vault passphrase | — | **Argon2id** (64 MiB, 3 iters) | — |

All primitives come from a single pinned, audited dependency: **BouncyCastle 1.80** (lightweight API — no JCE provider registration, no reflection surface). No custom primitives anywhere; only composition.

### Continuous key rotation ("ratchet by correspondence")

Every message you send **carries a brand-new KEM public key inside the encrypted, signed payload**:

```
outer:  ver | recipientKeyId(8) | ML-KEM ct | ephemeral X25519 pub | AEAD(inner)
inner:  senderFingerprint | counter | NEXT-KEM-PUBKEY | message | ML-DSA sig | Ed25519 sig
```

- The recipient adopts your new key for their next reply, and **keeps your previous keys in a window of 3** — so if a reply was written before your latest rotation arrived, it still decrypts (and is flagged `used old key`).
- Your own retired private keys are zeroed once they fall out of the window → **forward secrecy** at rotation granularity.
- Every round-trip heals the session → **post-compromise security**: an attacker who steals today's keys is locked out again after one exchange they can't observe.
- Because the rotation key rides *inside* the AEAD and under the dual signature, an attacker cannot inject a rogue rotation key without already having broken the current message.

Additional protocol properties:

- **Identity pinning** — the sender fingerprint inside the payload must match the contact you have on file; valid-but-wrong-sender messages are rejected.
- **Replay detection** — per-contact counter window (last 64); replays decrypt but are loudly flagged.
- **Domain separation** — every derived key uses an explicit `QPGP-v1/...` info string.
- **Rigid parsing** — length-prefixed binary format, hard caps on every field, trailing-garbage rejection, no text interpretation of untrusted input. QR frames feed the *same* strict parser as pasted text, so a malicious QR can do nothing a malicious paste couldn't.

### Vault at rest — two independent layers

```
plaintext state
  └─ ChaCha20-Poly1305  ← key = Argon2id(passphrase)          (layer 1)
      └─ AES-256-GCM    ← non-exportable Android Keystore key  (layer 2)
                           (StrongBox secure element when available)
```

An attacker needs **both** the physical, un-reset device **and** your passphrase. A forensic image of the flash without the hardware key is useless; the passphrase alone on another device is equally useless.

### QR identity exchange

An identity bundle (~5.7 KB armored) is too large for a single reliable phone-screen QR, so it is split into ~700-char frames that the sender's screen cycles through and the receiver's camera collects **in any order**. Each frame is bound to its payload by a hash prefix, so frames from different payloads can never be mixed. The `CAMERA` permission is runtime-requested **only** while the scan screen is open. After scanning, the verification-word ceremony (below) still applies.

### Biometric unlock (opt-in)

A fingerprint cannot *derive* a key. So qPGP seals your passphrase under a hardware Keystore AES key that (a) is non-exportable, (b) **requires biometric authentication for every use** (`BIOMETRIC_STRONG` + `setUserAuthenticationRequired`), and (c) is **invalidated the moment a new fingerprint is enrolled**. `BiometricPrompt` authenticates the decryption cipher itself, so the OS refuses the operation without a fresh successful biometric — the prompt can't be bypassed by UI tampering. **Tradeoff (stated in-app):** anyone with your device *and* an enrolled/coerced biometric can open the vault. The passphrase path always remains.

### Duress PIN (opt-in)

For on-the-spot coercion. Set a duress PIN in Settings (requires your real passphrase; the PIN must differ from it). If you are forced to open the app, enter the duress PIN at the **same** unlock screen:

- Your **real vault** — identity, all contacts, all private keys — is **instantly and irreversibly crypto-shredded** (the real hardware keystore key is destroyed; the vault file is 3-pass overwritten). This is the same guarantee as *Destroy vault*: no recovery.
- A **separate dummy vault**, keyed by that PIN under its own keystore key, opens in its place and lands on the normal Contacts screen — a working, empty app with no sign a real vault ever existed.
- **Indistinguishable from a real unlock:** the duress verifier is checked before the real-vault load, both run Argon2id (comparable timing), and there is no toast or visual tell. Only an Argon2id *verifier* of the PIN is stored, never the PIN.

Duress protects against being forced to unlock *now* — not against a forensic flash image captured *before* the trip.

### Vault destruction

*Settings → Destroy vault* (typed confirmation). Primary mechanism is **crypto-shredding**: the non-exportable hardware keystore keys are destroyed first, making every byte the app ever wrote to flash permanently undecryptable — even for a forensic lab imaging the raw storage, because what remains is AES-GCM ciphertext whose key no longer exists anywhere. Files are additionally 3-pass overwritten and deleted. This (hardware key destruction), not overwriting, is what carries the guarantee on flash storage with wear-leveling.

### Platform hardening

- **Minimal permissions.** Only `CAMERA` (QR scanning, runtime-requested only while scanning) and `USE_BIOMETRIC` (opt-in unlock). **No `INTERNET`** — the kernel refuses this app a socket. No storage, no contacts, no location, nothing else.
- `FLAG_SECURE` on every screen — no screenshots, no recents thumbnail, no screen casting.
- `allowBackup=false` + full data-extraction exclusion rules — nothing reaches cloud backup or device-to-device transfer.
- **The clipboard is never touched for secrets.** Decrypted plaintext has no copy button; only public outputs (ciphertext, identity blocks) can be copied, deliberately.
- Edge-to-edge insets handled so content never hides under the status bar / notch.
- Auto-lock after 3 minutes idle; passphrase and all private keys zeroed on lock.
- Keyboard fields set `NO_SUGGESTIONS` + `NO_PERSONALIZED_LEARNING` to limit IME leakage (an untrusted IME is still a risk — see below).
- All internal activities are `exported="false"`; attacker-supplied contact names are sanitized (control chars stripped, length-capped).

### Verification ceremony

Adding a contact — by paste or QR — only transfers public keys, which alone **cannot** rule out a man-in-the-middle who swapped the identity in transit. So qPGP immediately shows **six verification words** derived from both parties' fingerprints (order-independent — both of you see the same words). Compare them in person or over a voice channel you trust. Contacts stay loudly `UNVERIFIED` until you do.

---

## Honest residual risks (read this)

1. **A compromised OS/kernel defeats everything.** qPGP contains blast radius; it cannot make a rooted-by-malware phone safe. → *Run it on [GrapheneOS](#strongly-recommended-run-it-on-grapheneos), ideally a dedicated device.*
2. **The IME (keyboard) sees your plaintext as you type it.** Use a trusted keyboard; ideally a device without third-party IMEs.
3. **Whoever can read your screen reads your messages.** The analog hole is not solvable in software.
4. **Traffic analysis**: ciphertext you paste into another app reveals *that* you communicate, when, and roughly how much (sizes are not yet padded — planned).
5. **Flash forensics** may recover pre-shred vault *ciphertext*, but not its key (which lived only in the TEE). "Destroy" and the duress trip are crypto-shredding (keystore key deletion), the strongest primitive available on flash.
6. **Biometric & duress are tradeoffs, not magic.** Biometrics can be compelled more easily than a passphrase; duress defends against on-the-spot coercion, not prior full-image capture. Both are opt-in and documented in-app.
7. **PQC is young.** ML-KEM/ML-DSA could fall to new cryptanalysis; the hybrid design means security then rests on X25519/Ed25519 — solid classically, void against a future quantum computer. Formats are versioned for migration.
8. **This code has not undergone external cryptographic review.** Do not bet lives on it until it has.

---

## Roadmap

- [x] QR-code **identity** exchange (multi-frame, strict parser, no gallery import)
- [x] Contact editing (alias, verification, crypto-shred delete)
- [x] Biometric unlock (opt-in, hardware-gated)
- [x] Duress PIN (opt-in, indistinguishable dummy vault)
- [x] Vault destruction (crypto-shred + multi-pass overwrite)
- [ ] QR-code **message** exchange (same machinery, more frames)
- [ ] Ciphertext size padding (bucketed lengths, anti traffic-analysis)
- [ ] Passphrase-wrapped encrypted vault export (paper backup ceremony)
- [ ] Extract crypto to a shared **Rust core** (single source of truth for a future Linux port)
- [ ] Reproducible release builds
- [ ] **External cryptographic review** — release gate for v1.0

---

## Build & verify

```bash
# JDK 17+, Android SDK 35
./gradlew assembleDebug          # APK at app/build/outputs/apk/debug/
./gradlew testDebugUnitTest      # JVM tests: crypto round-trips, rotation, replay, forgery, QR framing
./verify.sh                      # canonical check: suite + APK build + security invariants
```

`verify.sh` runs the test suite and a fresh APK build, then asserts manifest permissions (no `INTERNET`, internal activities unexported), presence of key classes in the built dex, and the duress design invariants.

## License

MIT
