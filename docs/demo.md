# End-to-end software demo

This is the first crate that wires the protocol crate (`koffer-proto`) and the crypto crate (`koffer-crypto`) together. It runs the full signing-and-sealing flow in software, in both crypto profiles, and prints a short trace of every step.

The flow has two halves. First it builds a firmware-update manifest, signs it, and verifies the signature. Then it encrypts ("seals") a payload to a fresh recipient key and decrypts ("opens") it again. A few terms used below:

- **Manifest** -- a small record describing a firmware update: its version, a sequence number, the device class it targets, and a digest (a hash) of the firmware image. The format is SUIT, the IETF standard for firmware manifests.
- **COSE** -- the standard binary format for signed and encrypted messages, built on CBOR (a compact binary form of JSON). A `COSE_Sign1` carries one signature; a `COSE_Encrypt` carries encrypted content plus the key material the recipient needs to decrypt it.
- **Codepoint** -- every algorithm has a small integer identifier, its COSE codepoint, written into the message on the wire.

## Run it

```sh
cargo run -p koffer-demo
```

Output:

```text
KOFFER end-to-end demo

== Showcase: sig MlDsa65, kem X25519MlKem768, aead Aes256Gcm, kdf HkdfSha256 ==
  sign manifest -> COSE_Sign1 : 3384 bytes
  verify                      : OK
  seal payload -> COSE_Encrypt: 1186 bytes
  open                        : OK
  result                      : OK

== Cnsa20: sig MlDsa87, kem X25519MlKem1024, aead Aes256Gcm, kdf HkdfSha384 ==
  sign manifest -> COSE_Sign1 : 4702 bytes
  verify                      : OK
  seal payload -> COSE_Encrypt: 1666 bytes
  open                        : OK
  result                      : OK

all profiles: OK
```

The byte sizes differ between the profiles because each profile uses a different parameter set; the larger profile produces larger signatures and ciphertexts.

## What the flow does

**Sign and verify.**

1. Build the manifest and encode it.
2. Sign the encoded manifest with the profile's signature algorithm, then wrap the result as a `COSE_Sign1`.
3. Verify: decode the `COSE_Sign1`, read the signature algorithm's codepoint, select the matching verifier from that codepoint, and check the signature.

Flipping any byte of the signed message makes verification fail; the integration test checks this.

**Seal and open.**

1. Generate a fresh recipient key pair for the profile's key-encapsulation step.
2. Seal the payload: agree a shared secret with the recipient's public key (the KEM), derive an encryption key from that secret (the KDF), and encrypt the payload with an authenticated cipher (the AEAD). Frame the result as a `COSE_Encrypt`.
3. Open: decode the `COSE_Encrypt`, read the algorithm codepoints, select the matching backends, and decrypt.

Flipping any byte of the sealed message makes opening fail, because the cipher's authentication tag rejects it.

The three seal steps in plain terms:

- **KEM** (key-encapsulation mechanism) -- agrees a fresh shared secret using the recipient's public key.
- **KDF** (key-derivation function) -- turns that shared secret into the actual encryption key.
- **AEAD** (authenticated encryption) -- encrypts the payload and produces an authentication tag, so any tampering is detected on open.

## Crypto-agility

The signing and sealing side picks its algorithms from the profile. The verifying and opening side does not need to know the profile: it reads the integer codepoint carried in the message and selects the matching backend from that codepoint alone. This is the agility seam -- the wire format names the algorithm, so a verifier can handle whatever a signer chose, as long as it has that backend.

Switching the whole deployment between profiles is a single value change, with no per-algorithm edits to the flow.

## The two profiles

| Role | Showcase | Cnsa20 |
|------|----------|--------|
| Signature | ML-DSA-65 | ML-DSA-87 |
| Key encapsulation | X25519 + ML-KEM-768 | X25519 + ML-KEM-1024 |
| Authenticated encryption | AES-256-GCM | AES-256-GCM |
| Key derivation | HKDF-SHA256 | HKDF-SHA384 |

The key encapsulation is hybrid: it combines the classical X25519 key exchange with the post-quantum ML-KEM, so the shared secret stays safe if either one is later broken.
