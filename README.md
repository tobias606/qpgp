# ⬢ Kelopatra

**An offline, post-quantum, zero-permission vault for encrypting and decrypting sensitive messages on Android.**

Kelopatra is not a messenger. It has no network code and — more importantly — **no `INTERNET` permission**, so the Linux kernel itself refuses to give it a socket. It is a sealed room: you write a message, it comes out as armored ciphertext, and *you* choose how that ciphertext travels (paste it into any channel, print it, carry it on paper). Decryption happens the same way, in reverse.

---

## Security architecture

### Cryptography — hybrid everything, no compromises

Breaking any Kelopatra message requires breaking **both** a NIST post-quantum primitive **and** a mature classical primitive:

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
- **Domain separation** — every derived key uses an explicit `KELOPATRA-v1/...` info string.
- **Rigid parsing** — length-prefixed binary format, hard caps on every field, trailing-garbage rejection, no text interpretation of untrusted input.

### Vault at rest — two independent layers

```
plaintext state
  └─ ChaCha20-Poly1305  ← key = Argon2id(passphrase)          (layer 1)
      └─ AES-256-GCM    ← non-exportable Android Keystore key  (layer 2)
                           (StrongBox secure element when available)
```

An attacker needs **both** the physical, un-reset device **and** your passphrase. A forensic image of the flash without the hardware key is useless; the passphrase alone on another device is equally useless.

### Platform hardening

- **Zero permissions.** The manifest requests nothing. No INTERNET, no camera, no storage.
- `FLAG_SECURE` on every screen — no screenshots, no recents thumbnail, no screen casting.
- `allowBackup=false` + full data-extraction exclusion rules — nothing reaches cloud backup or device-to-device transfer.
- **The clipboard is never touched.** Ciphertext is shown as selectable text; copying is a deliberate user act.
- Auto-lock after 3 minutes idle; passphrase and all private keys zeroed on lock.
- Keyboard fields set `NO_SUGGESTIONS` + `NO_PERSONALIZED_LEARNING` to limit IME leakage (an untrusted IME is still a risk — see below).
- Attacker-supplied contact names are sanitized (control chars stripped, length-capped).

### Verification ceremony

Adding a contact only pastes public keys — that alone **cannot** rule out a man-in-the-middle who swapped the identity block in transit. So Kelopatra immediately shows **six verification words** derived from both parties' fingerprints (order-independent — both of you see the same words). Compare them in person or over a voice channel you trust. Contacts stay loudly `UNVERIFIED` until you do.

---

## Honest residual risks (read this)

1. **A compromised OS/kernel defeats everything.** Kelopatra contains blast radius; it cannot make a rooted-by-malware phone safe.
2. **The IME (keyboard) sees your plaintext as you type it.** Use a trusted keyboard; ideally a device without third-party IMEs.
3. **Whoever can read your screen reads your messages.** The analog hole is not solvable in software.
4. **Traffic analysis**: ciphertext you paste into another app reveals *that* you communicate, when, and roughly how much (sizes are not yet padded — planned).
5. **Flash forensics** may recover pre-overwrite vault states; "destroy" is crypto-shredding (keystore key deletion), which is the strongest primitive available on flash.
6. **PQC is young.** ML-KEM/ML-DSA could fall to new cryptanalysis; the hybrid design means security then rests on X25519/Ed25519 — solid classically, void against a future quantum computer. Formats are versioned for migration.
7. **This code has not undergone external cryptographic review.** Do not bet lives on it until it has.

## Roadmap

- [ ] QR-code identity & message exchange (multi-frame, sandboxed parser, no gallery import)
- [ ] Ciphertext size padding (bucketed lengths)
- [ ] Passphrase-wrapped encrypted vault export (paper backup ceremony)
- [ ] Reproducible release builds + signed releases

## Build

```bash
# JDK 17+, Android SDK 35
gradle assembleDebug          # APK at app/build/outputs/apk/debug/
gradle testDebugUnitTest      # JVM tests: crypto round-trips, rotation, replay, forgery rejection
```

## License

MIT
